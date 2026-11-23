import assert from "node:assert/strict";
import test from "node:test";
import { runSupervisedCommand, SupervisedCommandError } from "./worker-supervisor.js";

test("captures command output and exit status without invoking a shell", async () => {
  const result = await runSupervisedCommand(process.execPath, ["-e", "process.stdout.write('forgeos-worker-ok')"], {
    cwd: process.cwd(),
    timeoutMs: 5_000
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "forgeos-worker-ok");
  assert.equal(result.stderr, "");
});

test("bounds retained stdout and stderr output", async () => {
  const result = await runSupervisedCommand(process.execPath, ["-e", "process.stdout.write('x'.repeat(10000)); process.stderr.write('y'.repeat(10000))"], {
    cwd: process.cwd(),
    timeoutMs: 5_000,
    maxOutputBytes: 1_024
  });
  assert.equal(Buffer.byteLength(result.stdout), 1_024);
  assert.equal(Buffer.byteLength(result.stderr), 1_024);
});

test("timeout terminates the complete process group and reports bounded diagnostics", async () => {
  const script = "const {spawn}=require('node:child_process'); const c=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'}); console.log(c.pid); setInterval(()=>{},1000)";
  await assert.rejects(
    runSupervisedCommand(process.execPath, ["-e", script], {
      cwd: process.cwd(),
      timeoutMs: 250,
      terminationGraceMs: 100
    }),
    error => {
      assert.ok(error instanceof SupervisedCommandError);
      assert.equal(error.reason, "timeout");
      assert.match(error.stdout, /^\d+\s*$/);
      return true;
    }
  );
});

test("an already-aborted signal prevents command launch", async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    runSupervisedCommand(process.execPath, ["-e", "process.exit(0)"], {
      cwd: process.cwd(),
      timeoutMs: 5_000,
      signal: controller.signal
    }),
    error => error instanceof SupervisedCommandError && error.reason === "aborted"
  );
});
