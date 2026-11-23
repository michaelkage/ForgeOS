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
  BUILD_WORKER_SHARED_SECRET: z.string().min(32).optional(),
  GITHUB_TOKEN: z.string().optional()
});

export const config = envSchema.parse(process.env);
if (config.NODE_ENV === "production" && !config.COOKIE_SECURE) {
  throw new Error("COOKIE_SECURE must be true in production");
}
if (config.ENABLE_ANDROID_BUILDS && !config.BUILD_WORKER_SHARED_SECRET) {
  throw new Error("BUILD_WORKER_SHARED_SECRET (minimum 32 characters) is required when ENABLE_ANDROID_BUILDS=true");
}
