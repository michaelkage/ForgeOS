import assert from "node:assert/strict";
import test from "node:test";
import {
  assertProvisionedWorkerMatches,
  assertWorkerProviderEligible,
  provisionWorkerSafely,
  withDisposableWorker,
  validateWorkerProvisionRequest,
  type DisposableWorkerProvider,
  type WorkerProvisionRequest
} from "./worker-provider.js";

const request: WorkerProvisionRequest = {
  jobId: "123e4567-e89b-42d3-a456-426614174000",
  attempt: 1,
  architecture: "x64",
  romBase: "lineage",
  bootstrapCredential: "x".repeat(64),
  requirements: {
    disposable: true,
    singleJob: true,
    microVmOrDedicatedVm: true,
    nonRoot: true,
    noHostMounts: true,
    noContainerSocket: true,
    noPrivilegedMode: true,
    noHostPidNamespace: true,
    encryptedEphemeralDisk: true,
    destroyAfterJob: true,
    egressPolicyId: "android-build-egress-v1",
    workerImageDigest: "sha256:" + "a".repeat(64),
    resources: {
      cpuCores: 16,
      memoryMiB: 65_536,
      diskGiB: 500,
      processLimit: 4096,
      wallTimeSeconds: 43_200
    }
  }
};

const provider: DisposableWorkerProvider = {
  capabilities: {
    provider: "test-vm",
    isolation: {
      disposableVm: true,
      microVm: false,
      dedicatedKernel: true,
      encryptedEphemeralDisk: true,
      hardCpuLimit: true,
      hardMemoryLimit: true,
      hardDiskLimit: true,
      hardProcessLimit: true,
      wallClockLimit: true,
      egressFiltering: true,
      instanceMetadataBlocking: true,
      destroyGuarantee: true
    }
  },
  async provision() {
    throw new Error("not used in contract tests");
  },
  async terminate() {},
  async inspect() { return "stopped"; }
};

test("accepts a bounded Android worker request", () => {
  assert.doesNotThrow(() => validateWorkerProvisionRequest(request));
});

test("rejects undersized or excessive resource requests", () => {
  assert.throws(() => validateWorkerProvisionRequest({
    ...request,
    requirements: {
      ...request.requirements,
      resources: { ...request.requirements.resources, memoryMiB: 1024 }
    }
  }), /memoryMiB/);
  assert.throws(() => validateWorkerProvisionRequest({
    ...request,
    requirements: {
      ...request.requirements,
      resources: { ...request.requirements.resources, wallTimeSeconds: 999_999 }
    }
  }), /wallTimeSeconds/);
});

test("rejects runtime requests that disable a required isolation control", () => {
  const unsafe = {
    ...request,
    requirements: { ...request.requirements, noHostMounts: false }
  } as unknown as WorkerProvisionRequest;
  assert.throws(() => validateWorkerProvisionRequest(unsafe), /noHostMounts/);
});

test("rejects mutable image tags instead of immutable image digests", () => {
  assert.throws(() => validateWorkerProvisionRequest({
    ...request,
    requirements: { ...request.requirements, workerImageDigest: "latest" }
  }), /workerImageDigest/);
});

test("provider eligibility requires host-enforced isolation capabilities", () => {
  assert.doesNotThrow(() => assertWorkerProviderEligible(provider));
  const weakProvider = {
    ...provider,
    capabilities: {
      ...provider.capabilities,
      isolation: { ...provider.capabilities.isolation, hardMemoryLimit: false }
    }
  } as DisposableWorkerProvider;
  assert.throws(() => assertWorkerProviderEligible(weakProvider), /hardMemoryLimit/);
});

test("rejects a provider instance that does not match the requested job and image", () => {
  const instance = {
    provider: "test-vm",
    instanceId: "vm-123",
    jobId: request.jobId,
    attempt: request.attempt,
    architecture: "x64" as const,
    imageDigest: request.requirements.workerImageDigest,
    createdAt: new Date().toISOString()
  };
  assert.doesNotThrow(() => assertProvisionedWorkerMatches(request, instance));
  assert.throws(() => assertProvisionedWorkerMatches(request, {
    ...instance,
    jobId: "123e4567-e89b-42d3-a456-426614174001"
  }), /different job attempt/);
  assert.throws(() => assertProvisionedWorkerMatches(request, {
    ...instance,
    imageDigest: "sha256:" + "b".repeat(64)
  }), /unapproved image digest/);
});

test("tears down an instance if provider identity validation fails", async () => {
  let terminated = false;
  const mismatchedProvider: DisposableWorkerProvider = {
    ...provider,
    async provision() {
      return {
        provider: "unexpected-provider",
        instanceId: "vm-orphan",
        jobId: request.jobId,
        attempt: request.attempt,
        architecture: "x64",
        imageDigest: request.requirements.workerImageDigest,
        createdAt: new Date().toISOString()
      };
    },
    async terminate() { terminated = true; }
  };
  await assert.rejects(() => provisionWorkerSafely(mismatchedProvider, request), /different provider identity/);
  assert.equal(terminated, true);
});

test("disposable worker is terminated and shutdown-confirmed after success", async () => {
  const calls: string[] = [];
  const lifecycleProvider: DisposableWorkerProvider = {
    ...provider,
    async provision() {
      calls.push("provision");
      return {
        provider: "test-vm", instanceId: "vm-lifecycle", jobId: request.jobId,
        attempt: request.attempt, architecture: "x64",
        imageDigest: request.requirements.workerImageDigest,
        createdAt: new Date().toISOString()
      };
    },
    async inspect() { calls.push("inspect"); return calls.filter(x => x === "terminate").length ? "stopped" : "running"; },
    async terminate() { calls.push("terminate"); }
  };
  const value = await withDisposableWorker(lifecycleProvider, request, async () => {
    calls.push("operation");
    return "complete";
  });
  assert.equal(value, "complete");
  assert.deepEqual(calls, ["provision", "inspect", "operation", "terminate", "inspect"]);
});

test("disposable worker is terminated when its operation fails", async () => {
  let terminated = false;
  const lifecycleProvider: DisposableWorkerProvider = {
    ...provider,
    async provision() {
      return {
        provider: "test-vm", instanceId: "vm-failure", jobId: request.jobId,
        attempt: request.attempt, architecture: "x64",
        imageDigest: request.requirements.workerImageDigest,
        createdAt: new Date().toISOString()
      };
    },
    async inspect() { return terminated ? "stopped" : "running"; },
    async terminate() { terminated = true; }
  };
  await assert.rejects(() => withDisposableWorker(lifecycleProvider, request, async () => {
    throw new Error("guest execution failed");
  }), /guest execution failed/);
  assert.equal(terminated, true);
});

test("does not report success when provider cannot confirm VM teardown", async () => {
  const lifecycleProvider: DisposableWorkerProvider = {
    ...provider,
    async provision() {
      return {
        provider: "test-vm", instanceId: "vm-orphan-risk", jobId: request.jobId,
        attempt: request.attempt, architecture: "x64",
        imageDigest: request.requirements.workerImageDigest,
        createdAt: new Date().toISOString()
      };
    },
    async inspect() { return "unknown"; },
    async terminate() {}
  };
  await assert.rejects(() => withDisposableWorker(lifecycleProvider, request, async () => "must-not-succeed"), /shutdown/);
});
