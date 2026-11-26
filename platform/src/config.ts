import "dotenv/config";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(4100),
  HOST: z.string().default("127.0.0.1"),
  TRUST_PROXY: z.string().default("").transform(value => value.split(",").map(item => item.trim()).filter(Boolean)),
  DATABASE_URL: z.string().min(1),
  WEB_ORIGIN: z.string().url().default("http://127.0.0.1:4100"),
  MANIFEST_ROOT: z.string().default(fileURLToPath(new URL("../../", import.meta.url))),
  SESSION_COOKIE_NAME: z.string().default("forgeos_session"),
  SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(720).default(168),
  COOKIE_SECURE: z.string().default("false").transform(v => v === "true"),
  ENABLE_ANDROID_BUILDS: z.string().default("false").transform(v => v === "true"),
  BUILD_WORKER_SHARED_SECRET: z.preprocess(value => value === "" ? undefined : value, z.string().min(32).optional()),
  SIGNING_SERVICE_URL: z.preprocess(value => value === "" ? undefined : value, z.string().url().optional()),
  SIGNING_SERVICE_BEARER_TOKEN: z.preprocess(value => value === "" ? undefined : value, z.string().min(32).optional()),
  SIGNING_SERVICE_CLIENT_CERT: z.preprocess(value => value === "" ? undefined : value, z.string().min(1).optional()),
  SIGNING_SERVICE_CLIENT_KEY: z.preprocess(value => value === "" ? undefined : value, z.string().min(1).optional()),
  SIGNING_SERVICE_CA: z.preprocess(value => value === "" ? undefined : value, z.string().min(1).optional()),
  S3_ENDPOINT: z.preprocess(value => value === "" ? undefined : value, z.string().url().optional()),
  S3_REGION: z.preprocess(value => value === "" ? undefined : value, z.string().min(1).optional()),
  S3_BUCKET: z.preprocess(value => value === "" ? undefined : value, z.string().regex(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/).optional()),
  S3_ACCESS_KEY_ID: z.preprocess(value => value === "" ? undefined : value, z.string().min(1).optional()),
  S3_SECRET_ACCESS_KEY: z.preprocess(value => value === "" ? undefined : value, z.string().min(32).optional()),
  GITHUB_TOKEN: z.string().optional()
});

export const config = envSchema.parse(process.env);
if (config.NODE_ENV === "production" && !config.COOKIE_SECURE) {
  throw new Error("COOKIE_SECURE must be true in production");
}
const signingValues = [config.SIGNING_SERVICE_URL, config.SIGNING_SERVICE_BEARER_TOKEN,
  config.SIGNING_SERVICE_CLIENT_CERT, config.SIGNING_SERVICE_CLIENT_KEY, config.SIGNING_SERVICE_CA];
if (signingValues.some(Boolean) && !signingValues.every(Boolean)) {
  throw new Error("SIGNING_SERVICE_URL, SIGNING_SERVICE_BEARER_TOKEN, SIGNING_SERVICE_CLIENT_CERT, SIGNING_SERVICE_CLIENT_KEY, and SIGNING_SERVICE_CA must be configured together");
}
if (config.SIGNING_SERVICE_URL) {
  const signerUrl = new URL(config.SIGNING_SERVICE_URL);
  if (signerUrl.protocol !== "https:" || signerUrl.username || signerUrl.password || signerUrl.search || signerUrl.hash ||
      (signerUrl.pathname !== "" && signerUrl.pathname !== "/")) {
    throw new Error("SIGNING_SERVICE_URL must be credential-free HTTPS at the service origin");
  }
}
if (config.ENABLE_ANDROID_BUILDS && !signingValues.every(Boolean)) {
  throw new Error("A mutually authenticated isolated signing service is required when ENABLE_ANDROID_BUILDS=true");
}
if (config.ENABLE_ANDROID_BUILDS && !config.BUILD_WORKER_SHARED_SECRET) {
  throw new Error("BUILD_WORKER_SHARED_SECRET (minimum 32 characters) is required when ENABLE_ANDROID_BUILDS=true");
}

const storageValues = [config.S3_ENDPOINT, config.S3_REGION, config.S3_BUCKET, config.S3_ACCESS_KEY_ID, config.S3_SECRET_ACCESS_KEY];
if (storageValues.some(Boolean) && !storageValues.every(Boolean)) {
  throw new Error("S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY_ID, and S3_SECRET_ACCESS_KEY must be configured together");
}
if (config.ENABLE_ANDROID_BUILDS && !storageValues.every(Boolean)) {
  throw new Error("Private S3-compatible artifact storage is required when ENABLE_ANDROID_BUILDS=true");
}
