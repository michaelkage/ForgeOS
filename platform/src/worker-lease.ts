import { runSupervisedCommand, type SupervisedCommandOptions, type SupervisedCommandResult } from "./worker-supervisor.js";

export class WorkerLeaseLostError extends Error {
  constructor(readonly httpStatus: number | null, options?: ErrorOptions) {
    super(httpStatus === null ? "Worker control plane became unreachable" : "Worker lease was rejected by the control plane", options);
    this.name = "WorkerLeaseLostError";
  }
}

export interface LeasedCommandOptions extends Omit<SupervisedCommandOptions, "signal"> {
  apiBaseUrl: string;
  jobId: string;
  workerId: string;
  leaseToken: string;
  leaseSeconds?: number;
  heartbeatIntervalMs?: number;
  signal?: AbortSignal;
  fetchImpl?: typeof fetch;
}

async function sendHeartbeat(options: LeasedCommandOptions, fetchImpl: typeof fetch): Promise<void> {
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

/** Run one command while renewing its job lease. Any heartbeat failure aborts the process group. */
export async function runCommandWithLease(
  command: string,
  args: string[],
  options: LeasedCommandOptions
): Promise<SupervisedCommandResult> {
  const endpoint = new URL(options.apiBaseUrl);
  if (endpoint.protocol !== "https:") throw new TypeError("Worker control-plane URL must use HTTPS");
  if (!/^[0-9a-f-]{36}$/i.test(options.jobId) || !/^[0-9a-f-]{36}$/i.test(options.leaseToken)) {
    throw new TypeError("jobId and leaseToken must be UUIDs");
  }
  const intervalMs = options.heartbeatIntervalMs ?? 45_000;
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 5_000 || intervalMs > 120_000) {
    throw new RangeError("heartbeatIntervalMs must be between 5000 and 120000");
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  await sendHeartbeat(options, fetchImpl);
  if (options.signal?.aborted) throw new WorkerLeaseLostError(null);
  const controller = new AbortController();
  const forwardAbort = () => controller.abort(options.signal?.reason);
  options.signal?.addEventListener("abort", forwardAbort, { once: true });
  let leaseFailure: WorkerLeaseLostError | undefined;
  let heartbeatRunning = false;
  const timer = setInterval(() => {
    if (heartbeatRunning || leaseFailure || controller.signal.aborted) return;
    heartbeatRunning = true;
    void sendHeartbeat(options, fetchImpl).catch(error => {
      leaseFailure = error instanceof WorkerLeaseLostError ? error : new WorkerLeaseLostError(null, { cause: error });
      controller.abort(leaseFailure);
    }).finally(() => { heartbeatRunning = false; });
  }, intervalMs);
  timer.unref();
  try {
    const result = await runSupervisedCommand(command, args, {
      cwd: options.cwd, env: options.env, timeoutMs: options.timeoutMs,
      terminationGraceMs: options.terminationGraceMs, maxOutputBytes: options.maxOutputBytes,
      signal: controller.signal
    });
    if (leaseFailure) throw leaseFailure;
    return result;
  } catch (error) {
    if (leaseFailure) throw leaseFailure;
    throw error;
  } finally {
    clearInterval(timer);
    options.signal?.removeEventListener("abort", forwardAbort);
  }
}
