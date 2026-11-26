import { verify as verifySignature } from "node:crypto";

export interface GuestBootstrapPayload {
  schemaVersion: 1;
  jobId: string;
  attempt: number;
  architecture: "x86_64" | "arm64";
  imageDigest: string;
  apiBaseUrl: string;
  bootstrapCredential: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

export interface GuestBootstrapEnvelope {
  payload: GuestBootstrapPayload;
  signature: string;
}

export interface VerifiedGuestBootstrap {
  jobId: string;
  attempt: number;
  architecture: "x86_64" | "arm64";
  imageDigest: string;
  apiBaseUrl: URL;
  bootstrapCredential: string;
  nonce: string;
  expiresAt: number;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError("Bootstrap payload contains a non-JSON value");
    return encoded;
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const record = value as Record<string, unknown>;
  return "{" + Object.keys(record).sort().map(key => JSON.stringify(key) + ":" + canonicalJson(record[key])).join(",") + "}";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function validUuid(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

/**
 * Verifies the one-job credential delivered to a guest over the VM's
 * authenticated vsock bootstrap channel. This module does not expose a network
 * listener; the guest init process owns vsock framing and passes one bounded
 * decoded envelope here.
 */
export function verifyGuestBootstrap(
  input: unknown,
  pinnedHostPublicKeyPem: string,
  expected: { jobId: string; attempt: number; imageDigest: string; architecture: "x86_64" | "arm64" },
  now = Date.now()
): VerifiedGuestBootstrap {
  if (!isRecord(input) || !isRecord(input.payload) || typeof input.signature !== "string") {
    throw new TypeError("Guest bootstrap envelope is malformed");
  }
  const payload = input.payload as unknown as GuestBootstrapPayload;
  if (!pinnedHostPublicKeyPem.includes("BEGIN PUBLIC KEY")) {
    throw new TypeError("Pinned host-agent public key is required");
  }
  const signature = Buffer.from(input.signature, "base64");
  if (signature.length !== 64 ||
      !verifySignature(null, Buffer.from(canonicalJson(payload)), pinnedHostPublicKeyPem, signature)) {
    throw new Error("Guest bootstrap signature verification failed");
  }
  if (payload.schemaVersion !== 1 || !validUuid(payload.jobId) ||
      !Number.isSafeInteger(payload.attempt) || payload.attempt < 1 || payload.attempt > 20 ||
      (payload.architecture !== "x86_64" && payload.architecture !== "arm64") ||
      !/^sha256:[a-f0-9]{64}$/.test(payload.imageDigest)) {
    throw new TypeError("Guest bootstrap identity or schema is invalid");
  }
  if (payload.jobId !== expected.jobId || payload.attempt !== expected.attempt ||
      payload.architecture !== expected.architecture || payload.imageDigest !== expected.imageDigest) {
    throw new Error("Guest bootstrap is bound to a different job, attempt, architecture, or image");
  }
  let apiBaseUrl: URL;
  try { apiBaseUrl = new URL(payload.apiBaseUrl); } catch {
    throw new TypeError("Guest bootstrap API endpoint is invalid");
  }
  if (apiBaseUrl.protocol !== "https:" || apiBaseUrl.username || apiBaseUrl.password ||
      apiBaseUrl.search || apiBaseUrl.hash) {
    throw new TypeError("Guest bootstrap API endpoint must be a credential-free HTTPS URL");
  }
  if (typeof payload.bootstrapCredential !== "string" ||
      payload.bootstrapCredential.length < 32 || payload.bootstrapCredential.length > 4096) {
    throw new TypeError("Guest bootstrap credential is invalid");
  }
  if (typeof payload.nonce !== "string" || !/^[0-9a-f-]{36}$/i.test(payload.nonce)) {
    throw new TypeError("Guest bootstrap nonce is invalid");
  }
  const issuedAt = Date.parse(payload.issuedAt);
  const expiresAt = Date.parse(payload.expiresAt);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) ||
      issuedAt > now + 30_000 || now - issuedAt > 60_000 ||
      expiresAt <= now || expiresAt > now + 5 * 60_000 || expiresAt <= issuedAt) {
    throw new Error("Guest bootstrap envelope is expired or outside its validity window");
  }
  return {
    jobId: payload.jobId,
    attempt: payload.attempt,
    architecture: payload.architecture,
    imageDigest: payload.imageDigest,
    apiBaseUrl,
    bootstrapCredential: payload.bootstrapCredential,
    nonce: payload.nonce,
    expiresAt
  };
}
