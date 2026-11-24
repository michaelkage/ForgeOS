import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { verifyWorkerSnapshot, type WorkerBuildSnapshot } from "./worker-snapshot.js";

const manifest = '<manifest><remote name="github" fetch="https://github.com/" /></manifest>';
const snapshot: WorkerBuildSnapshot = {
  schemaVersion: 1,
  configuration: {
    id: "123e4567-e89b-42d3-a456-426614174000",
    name: "Test build",
    romBase: "lineage",
    rootMethod: "none",
    manifestRevision: "lineage-24.0",
    options: { includeGapps: false }
  },
  device: {
    id: "123e4567-e89b-42d3-a456-426614174001",
    codename: "example",
    manufacturer: "Example",
    model: "Example Phone",
    architecture: "arm64"
  },
  manifest: {
    path: "default.xml",
    branch: "lineage-24.0",
    sha256: createHash("sha256").update(manifest).digest("hex"),
    content: manifest
  },
  deviceTree: {
    repositoryUrl: "https://github.com/example/android_device_example_example",
    branch: "lineage-24.0",
    sourcePath: "",
    commitSha: "a".repeat(40)
  },
  sourceInputs: [{
    sourceKind: "kernel",
    romBase: "lineage",
    repositoryUrl: "https://github.com/example/android_kernel_example",
    branch: "lineage-24.0",
    sourcePath: "kernel",
    commitSha: "b".repeat(40)
  }],
  validationReport: { valid: true },
  configurationUpdatedAt: "2026-11-24T12:00:00.000Z"
};

function fingerprint(value: unknown): string {
  const canonical = (input: unknown): string => {
    if (input === null || typeof input !== "object") return JSON.stringify(input);
    if (Array.isArray(input)) return "[" + input.map(canonical).join(",") + "]";
    const record = input as Record<string, unknown>;
    return "{" + Object.keys(record).sort().map(key => JSON.stringify(key) + ":" + canonical(record[key])).join(",") + "}";
  };
  return createHash("sha256").update(canonical(value)).digest("hex");
}

test("verifies the immutable snapshot and embedded manifest digest", () => {
  const verified = verifyWorkerSnapshot(snapshot, fingerprint(snapshot));
  assert.equal(verified.deviceTree.commitSha, "a".repeat(40));
  assert.equal(verified.manifest.content, manifest);
});

test("rejects snapshot fingerprint tampering before trusting fields", () => {
  assert.throws(() => verifyWorkerSnapshot({ ...snapshot, device: { ...snapshot.device, codename: "tampered" } }, fingerprint(snapshot)), /fingerprint mismatch/);
});

test("rejects an embedded manifest whose bytes do not match its digest", () => {
  const changed = { ...snapshot, manifest: { ...snapshot.manifest, content: manifest + "<!-- changed -->" } };
  assert.throws(() => verifyWorkerSnapshot(changed, fingerprint(changed)), /manifest SHA-256 mismatch/);
});

test("rejects mutable or non-GitHub source URLs", () => {
  const changed = {
    ...snapshot,
    deviceTree: { ...snapshot.deviceTree, repositoryUrl: "http://github.com/example/device" }
  };
  assert.throws(() => verifyWorkerSnapshot(changed, fingerprint(changed)), /canonical HTTPS GitHub/);
});

test("rejects short commit identifiers and traversal source paths", () => {
  const shortSha = {
    ...snapshot,
    deviceTree: { ...snapshot.deviceTree, commitSha: "abc123" }
  };
  assert.throws(() => verifyWorkerSnapshot(shortSha, fingerprint(shortSha)), /full 40-character/);
  const traversal = {
    ...snapshot,
    sourceInputs: [{ ...snapshot.sourceInputs[0]!, sourcePath: "../outside" }]
  };
  assert.throws(() => verifyWorkerSnapshot(traversal, fingerprint(traversal)), /source path is unsafe/);
});

test("rejects unsupported schema versions and excessive source inputs", () => {
  const wrongVersion = { ...snapshot, schemaVersion: 2 };
  assert.throws(() => verifyWorkerSnapshot(wrongVersion, fingerprint(wrongVersion)), /schema version/);
  const excessive = { ...snapshot, sourceInputs: Array.from({ length: 101 }, (_, i) => ({
    ...snapshot.sourceInputs[0]!, repositoryUrl: "https://github.com/example/kernel-" + i
  })) };
  assert.throws(() => verifyWorkerSnapshot(excessive, fingerprint(excessive)), /too many source inputs/);
});
