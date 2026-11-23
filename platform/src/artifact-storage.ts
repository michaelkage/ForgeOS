import { createHash, createHmac } from "node:crypto";
import { config } from "./config.js";

const sha256 = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const hmac = (key: Buffer | string, value: string) => createHmac("sha256", key).update(value).digest();
const encode = (value: string) => encodeURIComponent(value).replace(/[!'()*]/g, c => "%" + c.charCodeAt(0).toString(16).toUpperCase());
const canonicalQuery = (values: Record<string, string>) => Object.entries(values)
  .sort(([a], [b]) => a.localeCompare(b))
  .map(([key, value]) => encode(key) + "=" + encode(value)).join("&");

function storageSettings() {
  const { S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY } = config;
  if (!S3_ENDPOINT || !S3_REGION || !S3_BUCKET || !S3_ACCESS_KEY_ID || !S3_SECRET_ACCESS_KEY) {
    throw new Error("Private S3 storage is not configured");
  }
  const endpoint = new URL(S3_ENDPOINT);
  if (endpoint.protocol !== "https:" && config.NODE_ENV === "production") {
    throw new Error("S3_ENDPOINT must use HTTPS in production");
  }
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error("S3_ENDPOINT must not contain credentials, query, or fragment");
  }
  return { endpoint, region: S3_REGION, bucket: S3_BUCKET, accessKey: S3_ACCESS_KEY_ID, secretKey: S3_SECRET_ACCESS_KEY };
}

export function isSafeArtifactObjectKey(key: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9/_.-]{2,511}$/.test(key) && key.split("/").every(part => part.length > 0 && part !== "." && part !== "..");
}

function objectUrl(key: string): URL {
  if (!isSafeArtifactObjectKey(key)) {
    throw new Error("Invalid private artifact object key");
  }
  const s = storageSettings();
  const url = new URL(s.endpoint);
  const prefix = url.pathname.replace(/\/$/, "");
  url.pathname = prefix + "/" + encode(s.bucket) + "/" + key.split("/").map(encode).join("/");
  return url;
}

function signingKey(secret: string, date: string, region: string): Buffer {
  const dateKey = hmac("AWS4" + secret, date);
  const regionKey = hmac(dateKey, region);
  const serviceKey = hmac(regionKey, "s3");
  return hmac(serviceKey, "aws4_request");
}

function signature(method: string, url: URL, headers: Record<string, string>, payloadHash: string, timestamp: Date): string {
  const s = storageSettings();
  const amzDate = timestamp.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const date = amzDate.slice(0, 8);
  const signedHeaders = Object.keys(headers).map(k => k.toLowerCase()).sort();
  const canonicalHeaders = signedHeaders.map(k => k + ":" + headers[k]!.trim().replace(/\s+/g, " ") + "\n").join("");
  const canonicalRequest = [method, url.pathname, url.searchParams.toString(), canonicalHeaders, signedHeaders.join(";"), payloadHash].join("\n");
  const scope = date + "/" + s.region + "/s3/aws4_request";
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonicalRequest)].join("\n");
  return createHmac("sha256", signingKey(s.secretKey, date, s.region)).update(stringToSign).digest("hex");
}

export function createArtifactUploadUrl(objectKey: string, sizeBytes: number, expiresSeconds = 600): string {
  const s = storageSettings(), url = objectUrl(objectKey), now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, ""), date = amzDate.slice(0, 8);
  const scope = date + "/" + s.region + "/s3/aws4_request";
  const headers = { host: url.host, "content-length": String(sizeBytes), "content-type": "application/zip", "if-none-match": "*" };
  const params: Record<string, string> = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": s.accessKey + "/" + scope,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expiresSeconds),
    "X-Amz-SignedHeaders": "content-length;content-type;host;if-none-match"
  };
  url.search = canonicalQuery(params);
  const signed = signature("PUT", url, headers, "UNSIGNED-PAYLOAD", now);
  url.search += "&X-Amz-Signature=" + signed;
  return url.toString();
}

export function createArtifactDownloadUrl(objectKey: string, expiresSeconds = 300): string {
  const s = storageSettings(), url = objectUrl(objectKey), now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, ""), date = amzDate.slice(0, 8);
  const scope = date + "/" + s.region + "/s3/aws4_request";
  url.search = canonicalQuery({
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": s.accessKey + "/" + scope,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expiresSeconds),
    "X-Amz-SignedHeaders": "host"
  });
  url.search += "&X-Amz-Signature=" + signature("GET", url, { host: url.host }, "UNSIGNED-PAYLOAD", now);
  return url.toString();
}

async function signedStorageRequest(method: "HEAD" | "GET", objectKey: string): Promise<Response> {
  const s = storageSettings(), url = objectUrl(objectKey), now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, ""), payloadHash = "UNSIGNED-PAYLOAD";
  const headers = {
    host: url.host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate
  };
  const auth = "AWS4-HMAC-SHA256 Credential=" + s.accessKey + "/" + amzDate.slice(0, 8) + "/" + s.region +
    "/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" +
    signature(method, url, headers, payloadHash, now);
  return fetch(url, { method, headers: { "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate, Authorization: auth }, signal: AbortSignal.timeout(45 * 60 * 1000), redirect: "error" });
}

export async function verifyUploadedArtifact(objectKey: string, expectedSize: number, expectedSha256: string): Promise<void> {
  const head = await signedStorageRequest("HEAD", objectKey);
  if (!head.ok) throw new Error("Artifact object is not present in private storage");
  const size = Number(head.headers.get("content-length"));
  const contentType = head.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  if (!Number.isSafeInteger(size) || size !== expectedSize || contentType !== "application/zip") {
    throw new Error("Stored artifact size or content type does not match its upload intent");
  }
  const response = await signedStorageRequest("GET", objectKey);
  if (!response.ok || !response.body) throw new Error("Artifact could not be read back for integrity verification");
  const digest = createHash("sha256");
  let bytes = 0;
  for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
    bytes += chunk.byteLength;
    if (bytes > expectedSize) {
      await response.body.cancel();
      throw new Error("Stored artifact exceeds its declared size");
    }
    digest.update(chunk);
  }
  if (bytes !== expectedSize || digest.digest("hex") !== expectedSha256) {
    throw new Error("Stored artifact SHA-256 verification failed");
  }
}
