import { runSupervisedCommand, type SupervisedCommandOptions, type SupervisedCommandResult } from "./worker-supervisor.js";

export class WorkerLeaseLostError extends Error {
  constructor(readonly httpStatus: number | null, options?: ErrorOptions) {
    super(httpStatus === null ? "Worker control plane became unreachable" : "Worker lease was rejected by the control plane", options);
    this.name = "WorkerLeaseLostError";
  }
}

export interface WorkerLeaseOptions {
  apiBaseUrl: string;
  jobId: string;
  workerId: string;
  leaseToken: string;
  leaseSeconds?: number;
  heartbeatIntervalMs?: number;
  signal?: AbortSignal;
  fetchImpl?: typeof fetch;
}

export interface WorkerLeaseContext {
  signal: AbortSignal;
  /** Call only after the API confirms successful job completion. */
  confirmCompletion(): void;
}

export interface LeasedCommandOptions extends WorkerLeaseOptions, Omit<SupervisedCommandOptions, "signal"> {}

async function sendHeartbeat(options: WorkerLeaseOptions, fetchImpl: typeof fetch): Promise<void> {
  const url = new URL("/api/internal/build-jobs/" + options.jobId + "/heartbeat", options.apiBaseUrl);
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: { authorization: "Bearer " + options.leaseToken, "content-type": "application/json" },
      body: JSON.stringify({ workerId: options.workerId, leaseToken: options.leaseToken, leaseSeconds: options.leaseSeconds ?? 180 }),
      signal: AbortSignal.timeout(15_000),
      redirect: "error"
    });
  } catch (error) {
    throw new WorkerLeaseLostError(null, { cause: error });
  }
  if (!response.ok) throw new WorkerLeaseLostError(response.status);
}

function validateLeaseOptions(options: WorkerLeaseOptions): void {
  const endpoint = new URL(options.apiBaseUrl);
  if (endpoint.protocol !== "https:") throw new TypeError("Worker control-plane URL must use HTTPS");
  if (!/^[0-9a-f-]{36}$/i.test(options.jobId) || !/^[0-9a-f-]{36}$/i.test(options.leaseToken)) {
    throw new TypeError("jobId and leaseToken must be UUIDs");
  }
  const intervalMs = options.heartbeatIntervalMs ?? 45_000;
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 5_000 || intervalMs > 120_000) {
    throw new RangeError("heartbeatIntervalMs must be between 5000 and 120000");
  }
}

/**
 * Holds a job lease across a complete worker operation (sync, build, artifact upload,
 * and completion). Any rejected or unreachable heartbeat aborts the supplied signal.
 * The operation must call confirmCompletion only after the API returns success.
 */
export async function withWorkerLease<T>(
  options: WorkerLeaseOptions,
  operation: (lease: WorkerLeaseContext) => Promise<T>
): Promise<T> {
  validateLeaseOptions(options);
  const fetchImpl = options.fetchImpl ?? fetch;
  await sendHeartbeat(options, fetchImpl);
  if (options.signal?.aborted) throw new WorkerLeaseLostError(null);

  const controller = new AbortController();
  const forwardAbort = () => controller.abort(options.signal?.reason);
  options.signal?.addEventListener("abort", forwardAbort, { once: true });
  let leaseFailure: WorkerLeaseLostError | undefined;
  let heartbeatRunning = false;
  let completed = false;
  let timer: NodeJS.Timeout | undefined;
  const stopHeartbeats = () => {
    if (timer) clearInterval(timer);
  };
  timer = setInterval(() => {
    if (heartbeatRunning || leaseFailure || completed || controller.signal.aborted) return;
    heartbeatRunning = true;
    void sendHeartbeat(options, fetchImpl).catch(error => {
      if (completed) return;
      leaseFailure = error instanceof WorkerLeaseLostError ? error : new WorkerLeaseLostError(null, { cause: error });
      controller.abort(leaseFailure);
    }).finally(() => { heartbeatRunning = false; });
  }, options.heartbeatIntervalMs ?? 45_000);

  try {
    const result = await operation({
      signal: controller.signal,
      confirmCompletion: () => {
        completed = true;
        stopHeartbeats();
      }
    });
    if (leaseFailure && !completed) throw leaseFailure;
    return result;
  } catch (error) {
    if (leaseFailure && !completed) throw leaseFailure;
    throw error;
  } finally {
    stopHeartbeats();
    options.signal?.removeEventListener("abort", forwardAbort);
  }
}

/** Run one command while renewing its job lease; use withWorkerLease for multi-step jobs. */
export async function runCommandWithLease(
  command: string,
  args: string[],
  options: LeasedCommandOptions
): Promise<SupervisedCommandResult> {
  return withWorkerLease(options, lease => runSupervisedCommand(command, args, {
    cwd: options.cwd, env: options.env, timeoutMs: options.timeoutMs,
    terminationGraceMs: options.terminationGraceMs, maxOutputBytes: options.maxOutputBytes,
    signal: lease.signal
  }));
}
