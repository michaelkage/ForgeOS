import { spawn } from "node:child_process";

export type CommandTermination = "timeout" | "aborted" | "spawn_error";

export interface SupervisedCommandOptions {
  cwd: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs: number;
  terminationGraceMs?: number;
  maxOutputBytes?: number;
  signal?: AbortSignal;
}

export interface SupervisedCommandResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  durationMs: number;
}

export class SupervisedCommandError extends Error {
  constructor(
    message: string,
    readonly reason: CommandTermination,
    readonly stdout: string,
    readonly stderr: string,
    readonly durationMs: number
  ) {
    super(message);
    this.name = "SupervisedCommandError";
  }
}

class BoundedTail {
  private value = Buffer.alloc(0);
  constructor(private readonly limit: number) {}

  append(chunk: Buffer): void {
    if (chunk.length >= this.limit) {
      this.value = chunk.subarray(chunk.length - this.limit);
      return;
    }
    const combined = Buffer.concat([this.value, chunk]);
    this.value = combined.length > this.limit ? combined.subarray(combined.length - this.limit) : combined;
  }

  text(): string {
    return this.value.toString("utf8");
  }
}

function signalProcessGroup(pid: number, signal: NodeJS.Signals): void {
  try {
    if (process.platform === "win32") process.kill(pid, signal);
    else process.kill(-pid, signal);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
  }
}

/**
 * Runs one command without a shell in a dedicated process group. Cancellation,
 * timeout, and normal leader exit all clean up descendants. This is a process
 * lifecycle primitive, not a security sandbox: production workers still need
 * a disposable VM/microVM and host-enforced cgroup limits.
 */
export function runSupervisedCommand(
  command: string,
  args: string[],
  options: SupervisedCommandOptions
): Promise<SupervisedCommandResult> {
  if (!command.trim() || !options.cwd) throw new TypeError("command and cwd are required");
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 24 * 60 * 60 * 1000) {
    throw new RangeError("timeoutMs must be between 1 ms and 24 hours");
  }
  const graceMs = options.terminationGraceMs ?? 5_000;
  const outputLimit = options.maxOutputBytes ?? 256 * 1024;
  if (!Number.isSafeInteger(graceMs) || graceMs < 0 || graceMs > 60_000) throw new RangeError("terminationGraceMs must be between 0 and 60000");
  if (!Number.isSafeInteger(outputLimit) || outputLimit < 1024 || outputLimit > 4 * 1024 * 1024) throw new RangeError("maxOutputBytes must be between 1 KiB and 4 MiB");
  if (options.signal?.aborted) {
    return Promise.reject(new SupervisedCommandError("Command aborted before start", "aborted", "", "", 0));
  }

  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const stdout = new BoundedTail(outputLimit);
    const stderr = new BoundedTail(outputLimit);
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      detached: process.platform !== "win32",
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let termination: CommandTermination | undefined;
    let spawnError: Error | undefined;
    let timeout: NodeJS.Timeout | undefined;
    let escalation: NodeJS.Timeout | undefined;
    let settled = false;

    const elapsed = () => Date.now() - startedAt;
    const terminate = (reason?: CommandTermination) => {
      if (reason && !termination) termination = reason;
      if (!child.pid) return;
      try {
        signalProcessGroup(child.pid, "SIGTERM");
      } catch {
        // A process that has already exited is treated as stopped.
      }
      if (!escalation && graceMs >= 0) {
        escalation = setTimeout(() => {
          if (child.pid) {
            try { signalProcessGroup(child.pid, "SIGKILL"); } catch { /* process group already exited */ }
          }
        }, graceMs);
        escalation.unref();
      }
    };
    const onAbort = () => terminate("aborted");

    child.stdout?.on("data", (chunk: Buffer) => stdout.append(chunk));
    child.stderr?.on("data", (chunk: Buffer) => stderr.append(chunk));
    child.once("error", error => {
      spawnError = error;
      terminate("spawn_error");
    });
    child.once("exit", () => {
      // A shell or build tool may leave grandchildren behind after its leader exits.
      terminate();
    });
    options.signal?.addEventListener("abort", onAbort, { once: true });
    timeout = setTimeout(() => terminate("timeout"), options.timeoutMs);
    timeout.unref();

    child.once("close", (exitCode, exitSignal) => {
      if (settled) return;
      settled = true;
      if (timeout) clearTimeout(timeout);
      if (escalation) clearTimeout(escalation);
      options.signal?.removeEventListener("abort", onAbort);
      const result = {
        exitCode,
        signal: exitSignal,
        stdout: stdout.text(),
        stderr: stderr.text(),
        durationMs: elapsed()
      };
      if (termination) {
        const message = termination === "timeout" ? "Command exceeded its execution deadline"
          : termination === "aborted" ? "Command was cancelled"
          : "Command could not be started";
        reject(new SupervisedCommandError(message, termination, result.stdout, result.stderr, result.durationMs));
      } else if (spawnError) {
        reject(new SupervisedCommandError(spawnError.message, "spawn_error", result.stdout, result.stderr, result.durationMs));
      } else {
        resolve(result);
      }
    });
  });
}
