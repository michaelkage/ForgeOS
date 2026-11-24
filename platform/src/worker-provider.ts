/**
 * Provider-neutral contract for disposable, single-job worker machines.
 *
 * This module deliberately provisions nothing. A provider adapter must implement
 * these interfaces and pass its own integration/security tests before it can be
 * selected by a production worker scheduler.
 */

export type WorkerArchitecture = "x86_64" | "arm64";

export interface WorkerResourceLimits {
  cpuCores: number;
  memoryMiB: number;
  diskGiB: number;
  processLimit: number;
  wallTimeSeconds: number;
}

export interface WorkerIsolationRequirements {
  disposable: true;
  singleJob: true;
  microVmOrDedicatedVm: true;
  nonRoot: true;
  noHostMounts: true;
  noContainerSocket: true;
  noPrivilegedMode: true;
  noHostPidNamespace: true;
  encryptedEphemeralDisk: true;
  destroyAfterJob: true;
  egressPolicyId: string;
  workerImageDigest: string;
  resources: WorkerResourceLimits;
}

export interface WorkerProvisionRequest {
  jobId: string;
  attempt: number;
  architecture: WorkerArchitecture;
  romBase: string;
  requirements: WorkerIsolationRequirements;
  /** Opaque, short-lived bootstrap material. Never persist or log this value. */
  bootstrapCredential: string;
}

export interface WorkerInstance {
  provider: string;
  instanceId: string;
  jobId: string;
  attempt: number;
  architecture: WorkerArchitecture;
  imageDigest: string;
  createdAt: string;
}

export interface WorkerProviderCapabilities {
  provider: string;
  isolation: {
    disposableVm: boolean;
    microVm: boolean;
    dedicatedKernel: boolean;
    encryptedEphemeralDisk: boolean;
    hardCpuLimit: boolean;
    hardMemoryLimit: boolean;
    hardDiskLimit: boolean;
    hardProcessLimit: boolean;
    wallClockLimit: boolean;
    egressFiltering: boolean;
    instanceMetadataBlocking: boolean;
    destroyGuarantee: boolean;
  };
}

export interface DisposableWorkerProvider {
  readonly capabilities: WorkerProviderCapabilities;
  provision(request: WorkerProvisionRequest, signal?: AbortSignal): Promise<WorkerInstance>;
  terminate(instance: WorkerInstance, reason: string): Promise<void>;
  inspect(instance: WorkerInstance): Promise<"running" | "stopped" | "unknown">;
}

const REQUIRED_ISOLATION: ReadonlyArray<keyof WorkerProviderCapabilities["isolation"]> = [
  "disposableVm",
  "dedicatedKernel",
  "encryptedEphemeralDisk",
  "hardCpuLimit",
  "hardMemoryLimit",
  "hardDiskLimit",
  "hardProcessLimit",
  "wallClockLimit",
  "egressFiltering",
  "instanceMetadataBlocking",
  "destroyGuarantee"
];

export function assertWorkerProviderEligible(provider: DisposableWorkerProvider): void {
  const missing = REQUIRED_ISOLATION.filter(key => provider.capabilities.isolation[key] !== true);
  if (missing.length > 0) {
    throw new Error("Worker provider does not meet isolation requirements: " + missing.join(", "));
  }
  if (!provider.capabilities.provider || provider.capabilities.provider.length > 80) {
    throw new TypeError("Worker provider must have a stable provider identifier");
  }
}

export function validateWorkerProvisionRequest(request: WorkerProvisionRequest): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(request.jobId)) {
    throw new TypeError("jobId must be a UUID");
  }
  if (!Number.isSafeInteger(request.attempt) || request.attempt < 1 || request.attempt > 20) {
    throw new RangeError("attempt must be between 1 and 20");
  }
  if (request.romBase.length < 1 || request.romBase.length > 64 || !/^[a-z0-9][a-z0-9._-]*$/.test(request.romBase)) {
    throw new TypeError("romBase is invalid");
  }
  if (request.bootstrapCredential.length < 32 || request.bootstrapCredential.length > 4096) {
    throw new TypeError("bootstrapCredential must be a bounded high-entropy credential");
  }
  const requiredControls: Array<keyof WorkerIsolationRequirements> = [
    "disposable", "singleJob", "microVmOrDedicatedVm", "nonRoot", "noHostMounts",
    "noContainerSocket", "noPrivilegedMode", "noHostPidNamespace",
    "encryptedEphemeralDisk", "destroyAfterJob"
  ];
  for (const control of requiredControls) {
    if (request.requirements[control] !== true) {
      throw new TypeError(control + " must be explicitly enabled");
    }
  }
  if (request.architecture !== "x86_64" && request.architecture !== "arm64") {
    throw new TypeError("architecture is unsupported");
  }
  const { resources } = request.requirements;
  const bounds: Array<[number, number, number, string]> = [
    [resources.cpuCores, 2, 128, "cpuCores"],
    [resources.memoryMiB, 4096, 1_048_576, "memoryMiB"],
    [resources.diskGiB, 100, 4096, "diskGiB"],
    [resources.processLimit, 128, 65_536, "processLimit"],
    [resources.wallTimeSeconds, 60, 172_800, "wallTimeSeconds"]
  ];
  for (const [value, min, max, name] of bounds) {
    if (!Number.isSafeInteger(value) || value < min || value > max) {
      throw new RangeError(name + " must be an integer between " + min + " and " + max);
    }
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(request.requirements.workerImageDigest)) {
    throw new TypeError("workerImageDigest must be a sha256 digest");
  }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(request.requirements.egressPolicyId)) {
    throw new TypeError("egressPolicyId is invalid");
  }
}

export function assertProvisionedWorkerMatches(
  request: WorkerProvisionRequest,
  instance: WorkerInstance
): void {
  if (instance.jobId !== request.jobId || instance.attempt !== request.attempt) {
    throw new Error("Provider returned a worker bound to a different job attempt");
  }
  if (instance.architecture !== request.architecture) {
    throw new Error("Provider returned a worker with the wrong architecture");
  }
  if (instance.imageDigest !== request.requirements.workerImageDigest) {
    throw new Error("Provider returned a worker with an unapproved image digest");
  }
  if (!instance.provider || !instance.instanceId || !Number.isFinite(Date.parse(instance.createdAt))) {
    throw new Error("Provider returned incomplete worker identity metadata");
  }
}

/**
 * Provision only through an eligible provider and destroy any instance whose
 * returned identity does not match the immutable request.
 */
export async function provisionWorkerSafely(
  provider: DisposableWorkerProvider,
  request: WorkerProvisionRequest,
  signal?: AbortSignal
): Promise<WorkerInstance> {
  assertWorkerProviderEligible(provider);
  validateWorkerProvisionRequest(request);
  const instance = await provider.provision(request, signal);
  try {
    assertProvisionedWorkerMatches(request, instance);
    if (instance.provider !== provider.capabilities.provider) {
      throw new Error("Provider returned an instance under a different provider identity");
    }
    return instance;
  } catch (validationError) {
    try {
      await provider.terminate(instance, "provisioned-instance-validation-failed");
    } catch (terminationError) {
      throw new AggregateError(
        [validationError, terminationError],
        "Worker instance failed validation and provider teardown also failed"
      );
    }
    throw validationError;
  }
}

/**
 * Owns a provisioned VM for exactly one operation. Teardown is mandatory on
 * success, failure, and cancellation; a provider that cannot confirm shutdown
 * causes the overall operation to fail rather than silently leaking compute.
 */
export async function withDisposableWorker<T>(
  provider: DisposableWorkerProvider,
  request: WorkerProvisionRequest,
  operation: (instance: WorkerInstance, signal?: AbortSignal) => Promise<T>,
  signal?: AbortSignal
): Promise<T> {
  const instance = await provisionWorkerSafely(provider, request, signal);
  let result!: T;
  let operationError: unknown;
  let operationFailed = false;
  try {
    if (signal?.aborted) throw signal.reason ?? new Error("Worker provisioning was cancelled");
    const state = await provider.inspect(instance);
    if (state !== "running") {
      throw new Error("Newly provisioned worker is not running");
    }
    // inspect() may yield to the event loop; cancellation during that await
    // must prevent guest code from starting, while still entering teardown.
    if (signal?.aborted) throw signal.reason ?? new Error("Worker provisioning was cancelled");
    result = await operation(instance, signal);
  } catch (error) {
    operationFailed = true;
    operationError = error;
  }

  let teardownError: unknown;
  try {
    await provider.terminate(instance, operationFailed ? "job-operation-failed" : "job-operation-finished");
    const state = await provider.inspect(instance);
    if (state !== "stopped") {
      throw new Error("Provider did not confirm worker shutdown after termination");
    }
  } catch (error) {
    teardownError = error;
  }

  if (operationFailed && teardownError !== undefined) {
    throw new AggregateError([operationError, teardownError], "Worker operation failed and VM shutdown (teardown) could not be confirmed");
  }
  if (teardownError !== undefined) {
    throw new AggregateError([teardownError], "VM shutdown (teardown) could not be confirmed");
  }
  if (operationFailed) throw operationError;
  return result;
}
