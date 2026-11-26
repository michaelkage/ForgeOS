import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { request as httpsRequest, Agent } from "node:https";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ClientRequest, IncomingMessage } from "node:http";
import { config } from "./config.js";
import {
  createArtifactDownloadUrl,
  createArtifactUploadUrl,
  verifyUploadedArtifact
} from "./artifact-storage.js";

const MAX_ARTIFACT_BYTES = 20 * 1024 * 1024 * 1024;
const SIGNING_TIMEOUT_MS = 2 * 60 * 60 * 1000;

export interface SignedArtifactRequest {
  userId: string;
  jobId: string;
  attempt: number;
  snapshotSha256: string;
  inputObjectKey: string;
  inputSha256: string;
  inputSizeBytes: number;
}
export interface SignedArtifactResult {
  objectKey: string;
  sha256: string;
  sizeBytes: number;
}

function requiredSignerConfig() {
  const { SIGNING_SERVICE_URL, SIGNING_SERVICE_BEARER_TOKEN, SIGNING_SERVICE_CLIENT_CERT,
    SIGNING_SERVICE_CLIENT_KEY, SIGNING_SERVICE_CA } = config;
  if (!SIGNING_SERVICE_URL || !SIGNING_SERVICE_BEARER_TOKEN || !SIGNING_SERVICE_CLIENT_CERT ||
      !SIGNING_SERVICE_CLIENT_KEY || !SIGNING_SERVICE_CA) {
    throw new Error("signing_service_unavailable: isolated signer is not configured");
  }
  return { url: new URL(SIGNING_SERVICE_URL), token: SIGNING_SERVICE_BEARER_TOKEN,
    certPath: SIGNING_SERVICE_CLIENT_CERT, keyPath: SIGNING_SERVICE_CLIENT_KEY, caPath: SIGNING_SERVICE_CA };
}

function responsePromise(request: ClientRequest): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    request.once("response", resolve);
    request.once("error", reject);
  });
}

async function sendToSigner(
  source: Readable,
  request: SignedArtifactRequest,
  agent: Agent,
  url: URL
): Promise<IncomingMessage> {
  const req = httpsRequest(url, {
    method: "POST",
    agent,
    signal: AbortSignal.timeout(SIGNING_TIMEOUT_MS),
    headers: {
      authorization: "Bearer " + requiredSignerConfig().token,
      "content-type": "application/zip",
      "content-length": String(request.inputSizeBytes),
      "x-forgeos-job-id": request.jobId,
      "x-forgeos-attempt": String(request.attempt),
      "x-forgeos-snapshot-sha256": request.snapshotSha256,
      "x-forgeos-artifact-sha256": request.inputSha256
    }
  });
  const response = responsePromise(req);
  const sent = pipeline(source, req);
  const [result] = await Promise.all([response, sent.then(() => undefined)]);
  return result;
}

async function uploadSignedOutput(url: string, sizeBytes: number, body: IncomingMessage): Promise<void> {
  const target = new URL(url);
  if (target.protocol !== "https:" || target.username || target.password) {
    throw new Error("signed artifact storage URL must use HTTPS");
  }
  const req = httpsRequest(target, {
    method: "PUT",
    headers: {
      "content-length": String(sizeBytes),
      "content-type": "application/zip",
      "if-none-match": "*"
    },
    signal: AbortSignal.timeout(SIGNING_TIMEOUT_MS)
  });
  const response = responsePromise(req);
  const sent = pipeline(body, req);
  const [result] = await Promise.all([response, sent.then(() => undefined)]);
  if (result.statusCode === 200 || result.statusCode === 201 || result.statusCode === 204) {
    result.resume();
    return;
  }
  result.resume();
  throw new Error("signed artifact storage upload failed with HTTP " + result.statusCode);
}

async function readErrorResponse(response: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of response) {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const remaining = 4096 - total;
    if (remaining > 0) chunks.push(data.subarray(0, remaining));
    total += data.length;
    if (total >= 4096) break;
  }
  return Buffer.concat(chunks).toString("utf8").replace(/[\r\n\t]+/g, " ").slice(0, 1000);
}

export async function signUploadedArtifact(input: SignedArtifactRequest): Promise<SignedArtifactResult> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(input.userId) ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(input.jobId) ||
      !Number.isInteger(input.attempt) || input.attempt < 1 || input.attempt > 20 ||
      !/^[a-f0-9]{64}$/.test(input.snapshotSha256) || !/^[a-f0-9]{64}$/.test(input.inputSha256) ||
      !Number.isSafeInteger(input.inputSizeBytes) || input.inputSizeBytes < 1 || input.inputSizeBytes > MAX_ARTIFACT_BYTES) {
    throw new Error("invalid signing request metadata");
  }
  const signer = requiredSignerConfig();
  const downloadUrl = createArtifactDownloadUrl(input.inputObjectKey, 600);
  const download = await fetch(downloadUrl, {
    redirect: "error",
    signal: AbortSignal.timeout(SIGNING_TIMEOUT_MS)
  });
  if (!download.ok || !download.body) {
    await download.body?.cancel().catch(() => undefined);
    throw new Error("signing_service_unavailable: verified source artifact could not be streamed from private storage");
  }
  const sourceSize = Number(download.headers.get("content-length"));
  const sourceType = download.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (sourceSize !== input.inputSizeBytes || sourceType !== "application/zip") {
    await download.body.cancel();
    throw new Error("signed artifact source metadata changed after verification");
  }

  const [cert, key, ca] = await Promise.all([
    readFile(signer.certPath), readFile(signer.keyPath), readFile(signer.caPath)
  ]);
  const agent = new Agent({ cert, key, ca, minVersion: "TLSv1.3", rejectUnauthorized: true });
  try {
    const signerUrl = new URL("/v1/sign", signer.url);
    const signed = await sendToSigner(
      Readable.fromWeb(download.body as import("node:stream/web").ReadableStream<Uint8Array>),
      input, agent, signerUrl
    );
    const signerStatus = signed.statusCode ?? 0;
    if (signerStatus !== 200) {
      const detail = await readErrorResponse(signed);
      const prefix = signerStatus === 422
        ? "artifact_signing_rejected: " : "signing_service_unavailable: ";
      throw new Error(prefix + "signer returned HTTP " + signerStatus + (detail ? " (" + detail + ")" : ""));
    }
    const sizeBytes = Number(signed.headers["content-length"]);
    const sha256 = signed.headers["x-forgeos-signed-sha256"];
    const contentType = signed.headers["content-type"]?.split(";")[0]?.trim().toLowerCase();
    if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 1 || sizeBytes > MAX_ARTIFACT_BYTES ||
        typeof sha256 !== "string" || !/^[a-f0-9]{64}$/.test(sha256) || contentType !== "application/zip") {
      signed.destroy();
      throw new Error("signing_service_unavailable: signer response metadata is invalid");
    }
    const objectKey = "artifacts/" + input.userId + "/" + input.jobId + "/" + input.attempt + "/" + randomUUID() + ".zip";
    const uploadUrl = createArtifactUploadUrl(objectKey, sizeBytes, 600);
    try {
      await uploadSignedOutput(uploadUrl, sizeBytes, signed);
    } catch (error) {
      throw new Error("artifact_storage_unavailable: " + (error instanceof Error ? error.message : "signed artifact upload failed"));
    }
    try {
      await verifyUploadedArtifact(objectKey, sizeBytes, sha256);
    } catch (error) {
      throw new Error("signed_artifact_verification_failed: " + (error instanceof Error ? error.message : "signed artifact verification failed"));
    }
    return { objectKey, sha256, sizeBytes };
  } catch (error) {
    if (error instanceof Error && /^(signing_service_unavailable:|artifact_signing_rejected:|artifact_storage_unavailable:|signed_artifact_verification_failed:)/.test(error.message)) throw error;
    throw new Error("signing_service_unavailable: " + (error instanceof Error ? error.message : "signer request failed"));
  } finally {
    agent.destroy();
  }
}
