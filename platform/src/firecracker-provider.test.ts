import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { FirecrackerWorkerProvider } from "./firecracker-provider.js";
import type { WorkerProvisionRequest } from "./worker-provider.js";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const now = Date.parse("2026-11-26T12:00:00.000Z");
const request: WorkerProvisionRequest = {
  jobId: "123e4567-e89b-42d3-a456-426614174000",
  attempt: 2,
  architecture: "x86_64",
  romBase: "lineage",
  bootstrapCredential: "b".repeat(64),
  requirements: {
    disposable: true, singleJob: true, microVmOrDedicatedVm: true, nonRoot: true,
    noHostMounts: true, noContainerSocket: true, noPrivilegedMode: true,
    noHostPidNamespace: true, encryptedEphemeralDisk: true, destroyAfterJob: true,
    egressPolicyId: "android-build-egress-v1",
    workerImageDigest: "sha256:" + "a".repeat(64),
    resources: { cpuCores: 16, memoryMiB: 65536, diskGiB: 500, processLimit: 4096, wallTimeSeconds: 43200 }
  }
};

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const record = value as Record<string, unknown>;
  return "{" + Object.keys(record).sort().map(key => JSON.stringify(key) + ":" + canonicalJson(record[key])).join(",") + "}";
}

function signed(value: unknown): string {
  return sign(null, Buffer.from(canonicalJson(value)), privateKey).toString("base64");
}

function makeFetch(handler: (url: URL, init: RequestInit) => unknown) {
  return async (input: string | URL | Request, init: RequestInit = {}) => {
    const body = handler(new URL(input.toString()), init);
    return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  };
}

function makeProvider(fetchImpl: typeof fetch) {
  return new FirecrackerWorkerProvider({
    endpoint: "https://host-agent.internal/",
    bearerToken: "s".repeat(64),
    attestationPublicKeyPem: publicKeyPem,
    fetchImpl,
    now: () => now
  });
}

function attestation(requestNonce: string, profileOverrides: Record<string, unknown> = {}) {
  return {
    provider: "forgeos-firecracker" as const,
    instanceId: "fc-vm-123",
    jobId: request.jobId,
    attempt: request.attempt,
    architecture: request.architecture,
    imageDigest: request.requirements.workerImageDigest,
    requestNonce,
    isolationProfile: {
      firecrackerMicroVm: true, dedicatedKernel: true, jailer: true, nonRootVmm: true,
      noHostMounts: true, noContainerSocket: true, noHostPidNamespace: true,
      encryptedEphemeralDisk: true, hardCpuLimit: true, hardMemoryLimit: true,
      hardDiskLimit: true, hardProcessLimit: true, wallTimeLimit: true,
      egressFiltering: true, metadataBlocked: true, destroyAfterJob: true,
      egressPolicyId: request.requirements.egressPolicyId,
      resources: request.requirements.resources,
      ...profileOverrides
    },
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString()
  };
}

test("requires HTTPS and a pinned host-agent identity", () => {
  assert.throws(() => new FirecrackerWorkerProvider({
    endpoint: "http://host-agent.internal",
    bearerToken: "s".repeat(64),
    attestationPublicKeyPem: publicKeyPem
  }), /HTTPS/);
  assert.throws(() => new FirecrackerWorkerProvider({
    endpoint: "https://host-agent.internal",
    bearerToken: "short",
    attestationPublicKeyPem: publicKeyPem
  }), /credential/);
});

test("provisions only after verifying signed exact-profile attestation", async () => {
  const fetchImpl = makeFetch((_url, init) => {
    const body = JSON.parse(String(init.body)) as { requestId: string };
    const payload = attestation(body.requestId);
    return {
      instance: {
        provider: "forgeos-firecracker", instanceId: "fc-vm-123", jobId: request.jobId,
        attempt: request.attempt, architecture: request.architecture,
        imageDigest: request.requirements.workerImageDigest, createdAt: new Date(now).toISOString()
      },
      attestation: { payload, signature: signed(payload) }
    };
  }) as typeof fetch;
  const provider = makeProvider(fetchImpl);
  const instance = await provider.provision(request);
  assert.equal(instance.instanceId, "fc-vm-123");
});

test("rejects an invalid signature and an attested policy weaker than requested", async () => {
  const invalidSignatureFetch = makeFetch((_url, init) => {
    const body = JSON.parse(String(init.body)) as { requestId: string };
    const payload = attestation(body.requestId);
    return {
      instance: { provider: "forgeos-firecracker", instanceId: "fc-vm-123", jobId: request.jobId,
        attempt: request.attempt, architecture: request.architecture,
        imageDigest: request.requirements.workerImageDigest, createdAt: new Date(now).toISOString() },
      attestation: { payload, signature: Buffer.alloc(64).toString("base64") }
    };
  }) as typeof fetch;
  await assert.rejects(() => makeProvider(invalidSignatureFetch).provision(request), /signature is invalid/);

  const weakProfileFetch = makeFetch((_url, init) => {
    const body = JSON.parse(String(init.body)) as { requestId: string };
    const payload = attestation(body.requestId, { egressFiltering: false });
    return {
      instance: { provider: "forgeos-firecracker", instanceId: "fc-vm-123", jobId: request.jobId,
        attempt: request.attempt, architecture: request.architecture,
        imageDigest: request.requirements.workerImageDigest, createdAt: new Date(now).toISOString() },
      attestation: { payload, signature: signed(payload) }
    };
  }) as typeof fetch;
  await assert.rejects(() => makeProvider(weakProfileFetch).provision(request), /exact requested isolation profile/);
});

test("rejects a stale attestation and binds the signed response to this request nonce", async () => {
  const staleFetch = makeFetch((_url, init) => {
    const body = JSON.parse(String(init.body)) as { requestId: string };
    const payload = { ...attestation(body.requestId), issuedAt: new Date(now - 120_000).toISOString() };
    return {
      instance: { provider: "forgeos-firecracker", instanceId: "fc-vm-123", jobId: request.jobId,
        attempt: request.attempt, architecture: request.architecture,
        imageDigest: request.requirements.workerImageDigest, createdAt: new Date(now).toISOString() },
      attestation: { payload, signature: signed(payload) }
    };
  }) as typeof fetch;
  await assert.rejects(() => makeProvider(staleFetch).provision(request), /outside its validity window/);
});

test("verifies signed VM state and termination acknowledgement", async () => {
  const instance = {
    provider: "forgeos-firecracker", instanceId: "fc-vm-123", jobId: request.jobId,
    attempt: request.attempt, architecture: request.architecture,
    imageDigest: request.requirements.workerImageDigest, createdAt: new Date(now).toISOString()
  };
  const fetchImpl = makeFetch((url, init) => {
    if (url.pathname.endsWith("/terminate")) {
      const body = JSON.parse(String(init.body)) as { requestId: string };
      const payload = { provider: instance.provider, instanceId: instance.instanceId, accepted: true, requestId: body.requestId };
      return { ...payload, signature: signed(payload) };
    }
    const payload = {
      provider: instance.provider, instanceId: instance.instanceId,
      state: "running", observedAt: new Date(now).toISOString()
    };
    return { ...payload, signature: signed(payload) };
  }) as typeof fetch;
  const provider = makeProvider(fetchImpl);
  assert.equal(await provider.inspect(instance), "running");
  await provider.terminate(instance, "job-finished");
});

test("forwards caller cancellation to the host-agent HTTP request", async () => {
  const controller = new AbortController();
  const fetchImpl = (async (_input: string | URL | Request, init: RequestInit = {}) => {
    controller.abort(new Error("lease lost"));
    if (init.signal?.aborted) throw init.signal.reason;
    throw new Error("abort signal was not forwarded");
  }) as typeof fetch;
  await assert.rejects(() => makeProvider(fetchImpl).provision(request, controller.signal), /lease lost/);
});
