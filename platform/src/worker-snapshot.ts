import { createHash, timingSafeEqual } from "node:crypto";

export interface PinnedWorkerSource {
  sourceKind: string;
  romBase: string | null;
  repositoryUrl: string;
  branch: string;
  sourcePath: string;
  commitSha: string;
}

export interface WorkerBuildSnapshot {
  schemaVersion: 1;
  configuration: {
    id: string;
    name: string;
    romBase: string;
    rootMethod: string;
    manifestRevision: string;
    options: unknown;
  };
  device: {
    id: string;
    codename: string;
    manufacturer: string;
    model: string;
    architecture: string;
  };
  manifest: {
    path: string;
    branch: string;
    sha256: string;
    content: string;
  };
  deviceTree: {
    repositoryUrl: string;
    branch: string;
    sourcePath: string;
    commitSha: string;
  };
  sourceInputs: PinnedWorkerSource[];
  validationReport: unknown;
  configurationUpdatedAt: string | Date;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new TypeError("Snapshot contains a non-finite number");
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError("Snapshot contains an unsupported value");
    return encoded;
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return "{" + Object.keys(record).sort().map(key => JSON.stringify(key) + ":" + canonicalJson(record[key])).join(",") + "}";
  }
  throw new TypeError("Snapshot must contain JSON values only");
}

function isSafeRelativePath(value: string, allowEmpty = false): boolean {
  if (allowEmpty && value === "") return true;
  if (!value || value.length > 512 || value.startsWith("/") || value.includes("\\") || /[\u0000-\u001f\u007f]/.test(value)) return false;
  const segments = value.split("/");
  return segments.every(segment => segment.length > 0 && segment !== "." && segment !== "..");
}

function assertPinnedGitHubRepository(value: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("Pinned source repository URL is invalid");
  }
  if (url.protocol !== "https:" || url.hostname !== "github.com" || url.username || url.password || url.search || url.hash) {
    throw new TypeError("Pinned source must use a canonical HTTPS GitHub repository URL");
  }
  const parts = url.pathname.replace(/\.git$/, "").split("/").filter(Boolean);
  if (parts.length !== 2 || parts.some(part => !/^[A-Za-z0-9_.-]+$/.test(part))) {
    throw new TypeError("Pinned source must identify exactly one GitHub owner and repository");
  }
}

function assertCommitSha(value: string): void {
  if (!/^[a-f0-9]{40}$/i.test(value)) throw new TypeError("Pinned source commit must be a full 40-character Git SHA");
}

export function verifyWorkerSnapshot(snapshot: unknown, expectedSha256: string): WorkerBuildSnapshot {
  if (!/^[a-f0-9]{64}$/.test(expectedSha256)) throw new TypeError("Expected snapshot SHA-256 is invalid");
  const actual = createHash("sha256").update(canonicalJson(snapshot)).digest();
  const expected = Buffer.from(expectedSha256, "hex");
  if (!timingSafeEqual(actual, expected)) throw new Error("Build snapshot fingerprint mismatch");

  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    throw new TypeError("Build snapshot must be an object");
  }
  const value = snapshot as Partial<WorkerBuildSnapshot>;
  if (value.schemaVersion !== 1) throw new TypeError("Unsupported build snapshot schema version");
  if (!value.configuration || !value.device || !value.manifest || !value.deviceTree || !Array.isArray(value.sourceInputs)) {
    throw new TypeError("Build snapshot is missing required sections");
  }
  if (!/^[0-9a-f-]{36}$/i.test(value.configuration.id) || !/^[0-9a-f-]{36}$/i.test(value.device.id)) {
    throw new TypeError("Build snapshot contains invalid configuration or device identity");
  }
  if (!isSafeRelativePath(value.manifest.path) || value.manifest.branch.length < 1 || value.manifest.branch.length > 255) {
    throw new TypeError("Build snapshot manifest reference is invalid");
  }
  if (!/^[a-f0-9]{64}$/.test(value.manifest.sha256) || typeof value.manifest.content !== "string") {
    throw new TypeError("Build snapshot manifest content or digest is invalid");
  }
  const manifestDigest = createHash("sha256").update(value.manifest.content, "utf8").digest("hex");
  if (manifestDigest !== value.manifest.sha256) throw new Error("Embedded manifest SHA-256 mismatch");

  const sources: PinnedWorkerSource[] = [
    {
      sourceKind: "device",
      romBase: value.configuration.romBase,
      repositoryUrl: value.deviceTree.repositoryUrl,
      branch: value.deviceTree.branch,
      sourcePath: value.deviceTree.sourcePath,
      commitSha: value.deviceTree.commitSha
    },
    ...value.sourceInputs
  ];
  if (sources.length > 101) throw new RangeError("Build snapshot contains too many source inputs");
  for (const source of sources) {
    if (!source || typeof source !== "object" || typeof source.repositoryUrl !== "string" ||
        typeof source.branch !== "string" || source.branch.length < 1 || source.branch.length > 255 ||
        typeof source.sourcePath !== "string" || typeof source.commitSha !== "string") {
      throw new TypeError("Build snapshot contains an invalid source input");
    }
    assertPinnedGitHubRepository(source.repositoryUrl);
    assertCommitSha(source.commitSha);
    if (!isSafeRelativePath(source.sourcePath, true)) throw new TypeError("Pinned source path is unsafe");
  }
  return value as WorkerBuildSnapshot;
}
