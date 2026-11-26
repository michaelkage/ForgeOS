import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { verifyGuestBootstrap } from "./guest-agent-bootstrap.js";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const now = Date.parse("2026-11-26T12:00:00.000Z");
const expected = {
  jobId: "123e4567-e89b-42d3-a456-426614174000",
  workerId: "forgeos-worker-01",
  attempt: 1,
  architecture: "x86_64" as const,
  imageDigest: "sha256:" + "a".repeat(64)
};

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const record = value as Record<string, unknown>;
  return "{" + Object.keys(record).sort().map(key => JSON.stringify(key) + ":" + canonicalJson(record[key])).join(",") + "}";
}

function envelope(overrides: Record<string, unknown> = {}) {
  const payload = {
    schemaVersion: 1,
    workerId: "forgeos-worker-01",
    ...expected,
    apiBaseUrl: "https://forgeos.example",
    bootstrapCredential: "c".repeat(64),
    nonce: "123e4567-e89b-42d3-a456-426614174099",
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 120_000).toISOString(),
    resources: { cpuCores: 4, memoryMiB: 8192, diskGiB: 200, processLimit: 2048, wallTimeSeconds: 3600 },
    ...overrides
  };
  return {
    payload,
    signature: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString("base64")
  };
}

test("accepts a correctly signed one-job guest bootstrap envelope", () => {
  const result = verifyGuestBootstrap(envelope(), publicKeyPem, expected, now);
  assert.equal(result.jobId, expected.jobId);
  assert.equal(result.workerId, expected.workerId);
  assert.equal(result.apiBaseUrl.href, "https://forgeos.example/");
  assert.equal(result.bootstrapCredential, "c".repeat(64));
});

test("rejects altered or untrusted bootstrap envelopes", () => {
  const valid = envelope();
  assert.throws(() => verifyGuestBootstrap({
    payload: { ...valid.payload, jobId: "123e4567-e89b-42d3-a456-426614174001" },
    signature: valid.signature
  }, publicKeyPem, expected, now), /signature verification failed/);
  assert.throws(() => verifyGuestBootstrap(envelope(), publicKeyPem, {
    ...expected, attempt: 2
  }, now), /different job/);
  assert.throws(() => verifyGuestBootstrap(envelope({ apiBaseUrl: "http://forgeos.example" }), publicKeyPem, expected, now), /HTTPS/);
});

test("rejects expired, overlong, or not-yet-valid bootstrap envelopes", () => {
  assert.throws(() => verifyGuestBootstrap(envelope({
    expiresAt: new Date(now - 1).toISOString()
  }), publicKeyPem, expected, now), /expired/);
  assert.throws(() => verifyGuestBootstrap(envelope({
    issuedAt: new Date(now - 120_000).toISOString()
  }), publicKeyPem, expected, now), /validity window/);
  assert.throws(() => verifyGuestBootstrap(envelope({
    expiresAt: new Date(now + 10 * 60_000).toISOString()
  }), publicKeyPem, expected, now), /validity window/);
});

test("rejects malformed credentials and unsupported endpoint schemes", () => {
  assert.throws(() => verifyGuestBootstrap(envelope({
    bootstrapCredential: "short"
  }), publicKeyPem, expected, now), /credential/);
  assert.throws(() => verifyGuestBootstrap(envelope({
    apiBaseUrl: "file:///etc/passwd"
  }), publicKeyPem, expected, now), /HTTPS/);
});
