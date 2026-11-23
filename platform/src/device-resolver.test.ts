import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { deviceSourceSchema, verifyDeviceSource } from "./device-resolver.js";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

const validDeviceSource = {
  sourceKind: "device" as const,
  repositoryUrl: "https://github.com/LineageOS/android_device_example",
  branchName: "lineage-24.0",
  sourcePath: ""
};

test("device source schema rejects non-GitHub hosts and traversal paths", () => {
  assert.equal(deviceSourceSchema.safeParse(validDeviceSource).success, true);
  assert.equal(deviceSourceSchema.safeParse({ ...validDeviceSource, repositoryUrl: "https://evil.example/owner/repo" }).success, false);
  assert.equal(deviceSourceSchema.safeParse({ ...validDeviceSource, sourcePath: "../secrets" }).success, false);
  assert.equal(deviceSourceSchema.safeParse({ ...validDeviceSource, repositoryUrl: "https://user:pass@github.com/owner/repo" }).success, false);
});

test("device resolver verifies a public device tree and pins the resolved commit", async () => {
  const sha = "0123456789abcdef0123456789abcdef01234567";
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.endsWith("/repos/LineageOS/android_device_example")) {
      return new Response(JSON.stringify({ archived: false, disabled: false }), { status: 200 });
    }
    if (url.includes("/branches/lineage-24.0")) {
      return new Response(JSON.stringify({ commit: { sha } }), { status: 200 });
    }
    if (url.includes("/contents?ref=lineage-24.0")) {
      return new Response(JSON.stringify([
        { name: "AndroidProducts.mk", type: "file" },
        { name: "BoardConfig.mk", type: "file" },
        { name: "device.mk", type: "file" }
      ]), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  const result = await verifyDeviceSource(validDeviceSource);
  assert.equal(result.status, "verified");
  assert.equal(result.commitSha, sha);
  assert.deepEqual(result.files.sort(), ["AndroidProducts.mk", "BoardConfig.mk", "device.mk"]);
});

test("device resolver fails closed when required device-tree files are absent", async () => {
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.endsWith("/repos/LineageOS/android_device_example")) return new Response("{}", { status: 200 });
    if (url.includes("/branches/lineage-24.0")) return new Response(JSON.stringify({ commit: { sha: "0123456789abcdef0123456789abcdef01234567" } }), { status: 200 });
    return new Response(JSON.stringify([{ name: "README.md", type: "file" }]), { status: 200 });
  }) as typeof fetch;
  const result = await verifyDeviceSource(validDeviceSource);
  assert.equal(result.status, "failed");
  assert.equal(result.commitSha, null);
  assert.match(result.error ?? "", /AndroidProducts\.mk/);
});

test("kernel source verification requires Makefile and Kconfig", async () => {
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.endsWith("/repos/owner/kernel")) return new Response("{}", { status: 200 });
    if (url.includes("/branches/main")) return new Response(JSON.stringify({ commit: { sha: "0123456789abcdef0123456789abcdef01234567" } }), { status: 200 });
    return new Response(JSON.stringify([{ name: "Makefile", type: "file" }]), { status: 200 });
  }) as typeof fetch;
  const result = await verifyDeviceSource({
    sourceKind: "kernel",
    repositoryUrl: "https://github.com/owner/kernel",
    branchName: "main",
    sourcePath: ""
  });
  assert.equal(result.status, "failed");
  assert.match(result.error ?? "", /Makefile and Kconfig/);
});
