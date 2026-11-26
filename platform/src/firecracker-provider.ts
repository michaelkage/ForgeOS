import { randomUUID, verify as verifySignature } from "node:crypto";
import {
  type DisposableWorkerProvider,
  type WorkerInstance,
  type WorkerProvisionRequest
} from "./worker-provider.js";

interface FirecrackerAttestation {
  provider: "forgeos-firecracker";
  instanceId: string;
  jobId: string;
  attempt: number;
  architecture: WorkerProvisionRequest["architecture"];
  imageDigest: string;
  requestNonce: string;
  isolationProfile: {
    firecrackerMicroVm: true;
    dedicatedKernel: true;
    jailer: true;
    nonRootVmm: true;
    noHostMounts: true;
    noContainerSocket: true;
    noHostPidNamespace: true;
    encryptedEphemeralDisk: true;
    hardCpuLimit: true;
    hardMemoryLimit: true;
    hardDiskLimit: true;
    hardProcessLimit: true;
    wallTimeLimit: true;
    egressFiltering: true;
    metadataBlocked: true;
    destroyAfterJob: true;
    egressPolicyId: string;
    resources: WorkerProvisionRequest["requirements"]["resources"];
  };
  issuedAt: string;
  expiresAt: string;
}

interface ProvisionResponse {
  instance: WorkerInstance;
  attestation: { payload: FirecrackerAttestation; signature: string };
}

interface StateResponse {
  provider: string;
  instanceId: string;
  state: "running" | "stopped" | "unknown";
  observedAt: string;
  signature: string;
}

interface TerminateResponse {
  provider: string;
  instanceId: string;
  accepted: true;
  requestId: string;
  signature: string;
}

export interface FirecrackerProviderOptions {
  /** HTTPS endpoint for the privileged host-side ForgeOS VM agent. */
  endpoint: string;
  /** Dedicated service credential; never a user or guest credential. */
  bearerToken: string;
  /** Ed25519 public key pinned out-of-band from the host agent deployment. */
  attestationPublicKeyPem: string;
  fetchImpl?: typeof fetch;
  now?: () => number;
  requestTimeoutMs?: number;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError("Cannot sign a non-JSON value");
    return encoded;
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const record = value as Record<string, unknown>;
  return "{" + Object.keys(record).sort().map(key => JSON.stringify(key) + ":" + canonicalJson(record[key])).join(",") + "}";
}

function equalJson(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function verifySignedPayload(payload: unknown, signatureBase64: unknown, publicKeyPem: string, label: string): void {
  if (!isRecord(payload) || typeof signatureBase64 !== "string") {
    throw new Error("Firecracker host agent returned a malformed " + label);
  }
  const signature = Buffer.from(signatureBase64, "base64");
  if (signature.length !== 64 ||
      !verifySignature(null, Buffer.from(canonicalJson(payload)), publicKeyPem, signature)) {
    throw new Error("Firecracker host agent " + label + " signature is invalid");
  }
}

function parseTimestamp(value: unknown, label: string): number {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw new Error("Firecracker host agent " + label + " timestamp is invalid");
  }
  return Date.parse(value);
}

function assertRecentTimestamp(value: unknown, now: number, maxAgeMs: number, label: string): void {
  const timestamp = parseTimestamp(value, label);
  if (timestamp > now + 30_000 || now - timestamp > maxAgeMs) {
    throw new Error("Firecracker host agent " + label + " timestamp is outside its validity window");
  }
}

export class FirecrackerWorkerProvider implements DisposableWorkerProvider {
  readonly capabilities = {
    provider: "forgeos-firecracker",
    isolation: {
      disposableVm: true,
      microVm: true,
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
  } as const;

  private readonly endpoint: URL;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly timeoutMs: number;

  constructor(private readonly options: FirecrackerProviderOptions) {
    this.endpoint = new URL(options.endpoint);
    if (this.endpoint.protocol !== "https:") throw new TypeError("Firecracker host agent endpoint must use HTTPS");
    if (this.endpoint.username || this.endpoint.password || this.endpoint.search || this.endpoint.hash) {
      throw new TypeError("Firecracker host agent endpoint must not contain credentials, query, or fragment");
    }
    if (options.bearerToken.length < 32 || options.bearerToken.length > 4096) {
      throw new TypeError("Firecracker host agent credential must be a bounded secret");
    }
    if (!options.attestationPublicKeyPem.includes("BEGIN PUBLIC KEY")) {
      throw new TypeError("A pinned Ed25519 host-agent public key is required");
    }
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? Date.now;
    this.timeoutMs = options.requestTimeoutMs ?? 15_000;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 100 || this.timeoutMs > 120_000) {
      throw new RangeError("requestTimeoutMs must be between 100 and 120000");
    }
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(new Error("Firecracker host agent request timed out")), this.timeoutMs);
    const signal = init.signal
      ? AbortSignal.any([controller.signal, init.signal])
      : controller.signal;
    try {
      const response = await this.fetchImpl(new URL(path, this.endpoint), {
        ...init,
        headers: {
          authorization: "Bearer " + this.options.bearerToken,
          accept: "application/json",
          ...(init.body ? { "content-type": "application/json" } : {}),
          ...init.headers
        },
        redirect: "error",
        signal
      });
      if (!response.ok) throw new Error("Firecracker host agent request failed with HTTP " + response.status);
      const length = Number(response.headers.get("content-length") ?? 0);
      if (length > 64 * 1024) throw new Error("Firecracker host agent response exceeded its size limit");
      const body = await response.text();
      if (Buffer.byteLength(body, "utf8") > 64 * 1024) throw new Error("Firecracker host agent response exceeded its size limit");
      return JSON.parse(body) as T;
    } finally {
      clearTimeout(timeout);
    }
  }

  async provision(request: WorkerProvisionRequest, signal?: AbortSignal): Promise<WorkerInstance> {
    if (signal?.aborted) throw signal.reason ?? new Error("Worker provisioning cancelled");
    const requestNonce = randomUUID();
    const response = await this.request<ProvisionResponse>("/v1/workers", {
      method: "POST",
      body: JSON.stringify({
        requestId: requestNonce,
        jobId: request.jobId,
        attempt: request.attempt,
        architecture: request.architecture,
        romBase: request.romBase,
        imageDigest: request.requirements.workerImageDigest,
        resources: request.requirements.resources,
        egressPolicyId: request.requirements.egressPolicyId,
        bootstrapCredential: request.bootstrapCredential
      }),
      signal
    });
    if (signal?.aborted) throw signal.reason ?? new Error("Worker provisioning cancelled");
    if (!isRecord(response) || !isRecord(response.instance) || !isRecord(response.attestation)) {
      throw new Error("Firecracker host agent returned a malformed provisioning response");
    }
    const attestation = response.attestation.payload;
    verifySignedPayload(attestation, response.attestation.signature, this.options.attestationPublicKeyPem, "provisioning attestation");
    const instance = response.instance as unknown as WorkerInstance;
    const now = this.now();
    assertRecentTimestamp(attestation.issuedAt, now, 60_000, "attestation issue");
    const expiry = parseTimestamp(attestation.expiresAt, "attestation expiry");
    if (expiry <= now || expiry > now + 5 * 60_000) {
      throw new Error("Firecracker host agent attestation expiry is invalid");
    }
    const expectedProfile = {
      firecrackerMicroVm: true,
      dedicatedKernel: true,
      jailer: true,
      nonRootVmm: true,
      noHostMounts: true,
      noContainerSocket: true,
      noHostPidNamespace: true,
      encryptedEphemeralDisk: true,
      hardCpuLimit: true,
      hardMemoryLimit: true,
      hardDiskLimit: true,
      hardProcessLimit: true,
      wallTimeLimit: true,
      egressFiltering: true,
      metadataBlocked: true,
      destroyAfterJob: true,
      egressPolicyId: request.requirements.egressPolicyId,
      resources: request.requirements.resources
    };
    if (!equalJson(attestation.isolationProfile, expectedProfile)) {
      throw new Error("Firecracker host agent did not attest the exact requested isolation profile");
    }
    if (attestation.provider !== this.capabilities.provider || attestation.instanceId !== instance.instanceId ||
        attestation.jobId !== request.jobId || attestation.attempt !== request.attempt ||
        attestation.architecture !== request.architecture ||
        attestation.imageDigest !== request.requirements.workerImageDigest ||
        attestation.requestNonce !== requestNonce ||
        instance.provider !== this.capabilities.provider || instance.jobId !== request.jobId ||
        instance.attempt !== request.attempt || instance.architecture !== request.architecture ||
        instance.imageDigest !== request.requirements.workerImageDigest) {
      throw new Error("Firecracker host agent attestation does not match the provisioning request");
    }
    return instance;
  }

  async inspect(instance: WorkerInstance): Promise<"running" | "stopped" | "unknown"> {
    const response = await this.request<StateResponse>(
      "/v1/workers/" + encodeURIComponent(instance.instanceId),
      { method: "GET" }
    );
    const payload = {
      provider: response.provider,
      instanceId: response.instanceId,
      state: response.state,
      observedAt: response.observedAt
    };
    verifySignedPayload(payload, response.signature, this.options.attestationPublicKeyPem, "VM state");
    assertRecentTimestamp(response.observedAt, this.now(), 60_000, "VM state");
    if (response.provider !== instance.provider || response.instanceId !== instance.instanceId) {
      throw new Error("Firecracker host agent state refers to a different VM");
    }
    if (!["running", "stopped", "unknown"].includes(response.state)) {
      throw new Error("Firecracker host agent returned an invalid VM state");
    }
    return response.state;
  }

  async terminate(instance: WorkerInstance, reason: string): Promise<void> {
    if (!reason || reason.length > 200) throw new TypeError("Termination reason is invalid");
    const requestId = randomUUID();
    const response = await this.request<TerminateResponse>(
      "/v1/workers/" + encodeURIComponent(instance.instanceId) + "/terminate",
      { method: "POST", body: JSON.stringify({ requestId, reason }) }
    );
    const payload = {
      provider: response.provider,
      instanceId: response.instanceId,
      accepted: response.accepted,
      requestId: response.requestId
    };
    verifySignedPayload(payload, response.signature, this.options.attestationPublicKeyPem, "termination acknowledgement");
    if (response.provider !== instance.provider || response.instanceId !== instance.instanceId ||
        response.accepted !== true || response.requestId !== requestId) {
      throw new Error("Firecracker host agent termination acknowledgement does not match the request");
    }
  }
}
