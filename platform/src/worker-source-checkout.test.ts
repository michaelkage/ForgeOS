import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkoutPinnedSources } from "./worker-source-checkout.js";
import type { WorkerBuildSnapshot } from "./worker-snapshot.js";
import type { SupervisedCommandResult } from "./worker-supervisor.js";

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError("Unsupported test snapshot value");
    return encoded;
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const record = value as Record<string, unknown>;
  return "{" + Object.keys(record).sort().map(key => JSON.stringify(key) + ":" + canonicalJson(record[key])).join(",") + "}";
}

const sha = "a".repeat(40);
const snapshot: WorkerBuildSnapshot = {
  schemaVersion: 1,
  configuration: {
    id: "123e4567-e89b-42d3-a456-426614174000",
    name: "Test",
    romBase: "lineage",
    rootMethod: "none",
    manifestRevision: "main",
    options: {}
  },
  device: {
    id: "123e4567-e89b-42d3-a456-426614174001",
    codename: "testdevice",
    manufacturer: "Test",
    model: "Test Device",
    architecture: "arm64"
  },
  manifest: {
    path: ".repo/local_manifests/forgeos.xml",
    branch: "main",
    sha256: createHash("sha256").update("<manifest />").digest("hex"),
    content: "<manifest />"
  },
  deviceTree: {
    repositoryUrl: "https://github.com/example/device_testdevice",
    branch: "mutable-branch-is-metadata-only",
    sourcePath: "device/testdevice",
    commitSha: sha
  },
  sourceInputs: [{
    sourceKind: "kernel",
    romBase: "lineage",
    repositoryUrl: "https://github.com/example/kernel_test",
    branch: "another-mutable-branch",
    sourcePath: "kernel/test",
    commitSha: "b".repeat(40)
  }],
  validationReport: {},
  configurationUpdatedAt: new Date(0).toISOString()
};
const snapshotSha256 = createHash("sha256").update(canonicalJson(snapshot)).digest("hex");

test("materializes exact manifest bytes and checks out only pinned commit IDs", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "forgeos-checkout-"));
  const calls: string[][] = [];
  try {
    const result = await checkoutPinnedSources(snapshot, snapshotSha256, {
      workspace,
      runCommand: async (_command, args): Promise<SupervisedCommandResult> => {
        calls.push(args);
        return {
          exitCode: 0,
          signal: null,
          stdout: args.includes("rev-parse") ? (args[1]?.endsWith("/000") ? sha : "b".repeat(40)) : "",
          stderr: "",
          durationMs: 1
        };
      }
    });

    assert.equal(await readFile(result.manifestPath, "utf8"), snapshot.manifest.content);
    assert.equal(result.checkouts.length, 2);
    assert.equal(result.checkouts[0]?.sourceDirectory.endsWith("device/testdevice"), true);
    assert.equal(result.checkouts[1]?.sourceDirectory.endsWith("kernel/test"), true);

    const fetches = calls.filter(args => args.includes("fetch"));
    assert.deepEqual(fetches.map(args => args.at(-1)), [sha, "b".repeat(40)]);
    assert.equal(calls.some(args => args.includes("mutable-branch-is-metadata-only") || args.includes("another-mutable-branch")), false);
    assert.equal(calls.filter(args => args.includes("rev-parse")).length, 2);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("refuses to overwrite an existing manifest", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "forgeos-checkout-existing-"));
  try {
    const manifest = join(workspace, snapshot.manifest.path);
    const { mkdir, writeFile } = await import("node:fs/promises");
    await mkdir(join(workspace, ".repo/local_manifests"), { recursive: true });
    await writeFile(manifest, "attacker-controlled");
    await assert.rejects(() => checkoutPinnedSources(snapshot, {
      workspace,
      runCommand: async () => {
        throw new Error("git must not run after manifest collision");
      }
    }), /EEXIST/);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("stops before the next source when cancellation is signalled", async () => {
  const workspace = await mkdtemp(join(tmpdir(), "forgeos-checkout-cancel-"));
  const controller = new AbortController();
  let commands = 0;
  try {
    await assert.rejects(() => checkoutPinnedSources(snapshot, {
      workspace,
      signal: controller.signal,
      runCommand: async (_command, args): Promise<SupervisedCommandResult> => {
        commands += 1;
        if (args.includes("rev-parse")) controller.abort(new Error("lease lost"));
        return {
          exitCode: 0, signal: null,
          stdout: args.includes("rev-parse") ? (args[1]?.endsWith("/000") ? sha : "b".repeat(40)) : "",
          stderr: "", durationMs: 1
        };
      }
    }), /lease lost/);
    assert.equal(commands, 4);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
