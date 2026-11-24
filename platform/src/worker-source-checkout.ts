import { mkdir, realpath, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { runSupervisedCommand, type SupervisedCommandResult } from "./worker-supervisor.js";
import { verifyWorkerSnapshot, type PinnedWorkerSource, type WorkerBuildSnapshot } from "./worker-snapshot.js";

export interface PinnedCheckout {
  source: PinnedWorkerSource;
  repositoryDirectory: string;
  sourceDirectory: string;
}

export interface CheckoutOptions {
  workspace: string;
  signal?: AbortSignal;
  commandTimeoutMs?: number;
  runCommand?: typeof runSupervisedCommand;
}

function assertContained(root: string, candidate: string): void {
  const rel = relative(root, candidate);
  if (!rel || rel === "." || rel.startsWith(".." + sep) || rel === ".." || isAbsolute(rel)) {
    throw new Error("Worker path escapes its assigned workspace");
  }
}

async function runGit(
  runner: typeof runSupervisedCommand,
  args: string[],
  cwd: string,
  timeoutMs: number,
  signal?: AbortSignal
): Promise<SupervisedCommandResult> {
  const result = await runner("git", args, {
    cwd,
    timeoutMs,
    maxOutputBytes: 256 * 1024,
    signal,
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      HOME: resolve(cwd, ".git-home"),
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
      GCM_INTERACTIVE: "Never"
    }
  });
  if (result.exitCode !== 0) {
    throw new Error("Pinned source git command failed (" + args[0] + "): " + result.stderr.slice(-4096));
  }
  return result;
}

/**
 * Fetches only immutable commit IDs from a previously verified snapshot.
 * No branch name is used to select source content. This function assumes it
 * runs inside the disposable guest VM; it is not a host-side sandbox.
 */
export async function checkoutPinnedSources(
  snapshotInput: unknown,
  expectedSnapshotSha256: string,
  options: CheckoutOptions
): Promise<{ manifestPath: string; checkouts: PinnedCheckout[] }> {
  const snapshot: WorkerBuildSnapshot = verifyWorkerSnapshot(snapshotInput, expectedSnapshotSha256);
  const runner = options.runCommand ?? runSupervisedCommand;
  const timeoutMs = options.commandTimeoutMs ?? 30 * 60 * 1000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2 * 60 * 60 * 1000) {
    throw new RangeError("commandTimeoutMs must be between 1 ms and 2 hours");
  }

  await mkdir(options.workspace, { recursive: true, mode: 0o700 });
  const workspace = await realpath(options.workspace);
  const home = resolve(workspace, ".git-home");
  await mkdir(home, { recursive: true, mode: 0o700 });

  const manifestPath = resolve(workspace, snapshot.manifest.path);
  assertContained(workspace, manifestPath);
  await mkdir(dirname(manifestPath), { recursive: true, mode: 0o700 });
  await writeFile(manifestPath, snapshot.manifest.content, { encoding: "utf8", flag: "wx", mode: 0o600 });

  const sources: PinnedWorkerSource[] = [
    {
      sourceKind: "device",
      romBase: snapshot.configuration.romBase,
      repositoryUrl: snapshot.deviceTree.repositoryUrl,
      branch: snapshot.deviceTree.branch,
      sourcePath: snapshot.deviceTree.sourcePath,
      commitSha: snapshot.deviceTree.commitSha
    },
    ...snapshot.sourceInputs
  ];

  const checkouts: PinnedCheckout[] = [];
  for (let index = 0; index < sources.length; index += 1) {
    if (options.signal?.aborted) throw options.signal.reason ?? new Error("Source checkout cancelled");
    const source = sources[index]!;
    const repositoryDirectory = resolve(workspace, "sources", String(index).padStart(3, "0"));
    assertContained(workspace, repositoryDirectory);
    await mkdir(dirname(repositoryDirectory), { recursive: true, mode: 0o700 });

    await runGit(runner, ["clone", "--no-checkout", "--filter=blob:none", "--no-tags", "--", source.repositoryUrl, repositoryDirectory],
      workspace, timeoutMs, options.signal);
    await runGit(runner, ["-C", repositoryDirectory, "fetch", "--no-tags", "--depth=1", "origin", source.commitSha],
      workspace, timeoutMs, options.signal);
    await runGit(runner, ["-C", repositoryDirectory, "checkout", "--detach", source.commitSha],
      workspace, timeoutMs, options.signal);

    const head = await runGit(runner, ["-C", repositoryDirectory, "rev-parse", "--verify", "HEAD"],
      workspace, timeoutMs, options.signal);
    if (head.stdout.trim().toLowerCase() !== source.commitSha.toLowerCase()) {
      throw new Error("Checked-out source HEAD does not match the immutable snapshot commit");
    }

    const sourceDirectory = resolve(repositoryDirectory, source.sourcePath);
    if (source.sourcePath) assertContained(repositoryDirectory, sourceDirectory);
    checkouts.push({ source, repositoryDirectory, sourceDirectory });
  }

  return { manifestPath, checkouts };
}
