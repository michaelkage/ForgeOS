import assert from "node:assert/strict";
import test from "node:test";
import { runCommandWithLease, withWorkerLease, WorkerLeaseLostError } from "./worker-lease.js";

const base = {
  apiBaseUrl: "https://forgeos.invalid",
  jobId: "00000000-0000-4000-8000-000000000001",
  workerId: "worker-eu-01",
  leaseToken: "00000000-0000-4000-8000-000000000002",
  cwd: process.cwd(),
  timeoutMs: 5_000,
  heartbeatIntervalMs: 5_000
};

test("renews lease before running a command and sends the per-job bearer token", async () => {
  let calls = 0;
  const fetchImpl: typeof fetch = async (_input, init) => {
    calls++;
    const headers = new Headers(init?.headers);
    assert.equal(headers.get("authorization"), "Bearer " + base.leaseToken);
    return new Response(null, { status: 204 });
  };
  const result = await runCommandWithLease(process.execPath, ["-e", "process.stdout.write(String.fromCharCode(108,101,97,115,101,45,111,107))"], { ...base, fetchImpl });
  assert.equal(result.stdout, "lease-ok");
  assert.equal(calls, 1);
});

test("does not launch a command when the initial lease heartbeat fails", async () => {
  const fetchImpl: typeof fetch = async () => new Response(null, { status: 409 });
  await assert.rejects(runCommandWithLease(process.execPath, ["-e", "process.exit(0)"], {
    ...base, fetchImpl
  }), error => error instanceof WorkerLeaseLostError && error.httpStatus === 409);
});

test("kills the running process group when a later heartbeat is rejected", async () => {
  let calls = 0;
  const fetchImpl: typeof fetch = async () => {
    calls++;
    return new Response(null, { status: calls === 1 ? 204 : 409 });
  };
  await assert.rejects(runCommandWithLease(process.execPath, ["-e", "setInterval(()=>{},1000)"], {
    ...base, heartbeatIntervalMs: 5_000, fetchImpl, timeoutMs: 20_000
  }), error => error instanceof WorkerLeaseLostError && error.httpStatus === 409);
  assert.ok(calls >= 2);
});

test("keeps heartbeating across non-command job phases and aborts on lease loss", async () => {
  let calls = 0;
  const fetchImpl: typeof fetch = async () => {
    calls++;
    return new Response(null, { status: calls === 1 ? 204 : 409 });
  };
  await assert.rejects(withWorkerLease({ ...base, fetchImpl }, async lease => {
    await new Promise<void>((resolve, reject) => {
      lease.signal.addEventListener("abort", () => reject(lease.signal.reason), { once: true });
    });
  }), error => error instanceof WorkerLeaseLostError && error.httpStatus === 409);
  assert.ok(calls >= 2);
});

test("stops lease heartbeats only after successful completion is confirmed", async () => {
  let calls = 0;
  const fetchImpl: typeof fetch = async () => {
    calls++;
    return new Response(null, { status: 204 });
  };
  const result = await withWorkerLease({ ...base, fetchImpl }, async lease => {
    lease.confirmCompletion();
    return "completed";
  });
  assert.equal(result, "completed");
  assert.equal(calls, 1);
});

test("rejects a callback that returns after its external cancellation signal aborts", async () => {
  const controller = new AbortController();
  const fetchImpl: typeof fetch = async () => new Response(null, { status: 204 });
  await assert.rejects(withWorkerLease({ ...base, fetchImpl, signal: controller.signal }, async () => {
    controller.abort(new Error("worker host cancelled the job"));
    return "incorrect-success";
  }), error => error instanceof WorkerLeaseLostError && error.httpStatus === null);
});

test("does not confirm completion after external cancellation", async () => {
  const controller = new AbortController();
  const fetchImpl: typeof fetch = async () => new Response(null, { status: 204 });
  await assert.rejects(withWorkerLease({ ...base, fetchImpl, signal: controller.signal }, async lease => {
    controller.abort(new Error("worker host cancelled the job"));
    lease.confirmCompletion();
  }), error => error instanceof WorkerLeaseLostError && error.httpStatus === null);
});
