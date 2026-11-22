import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(4100),
  HOST: z.string().default("127.0.0.1"),
  DATABASE_URL: z.string().min(1),
  WEB_ORIGIN: z.string().url().default("http://localhost:3000"),
  SESSION_COOKIE_NAME: z.string().default("forgeos_session"),
  SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(720).default(168),
  COOKIE_SECURE: z.string().default("false").transform(v => v === "true"),
  ENABLE_ANDROID_BUILDS: z.string().default("false").transform(v => v === "true")
});

export const config = envSchema.parse(process.env);
if (config.NODE_ENV === "production" && !config.COOKIE_SECURE) {
  throw new Error("COOKIE_SECURE must be true in production");
}
