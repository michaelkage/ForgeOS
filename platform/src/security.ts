import { createHash, randomBytes } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import argon2 from "argon2";
import { query } from "./db.js";
import { config } from "./config.js";

export interface SessionUser { id: string; email: string; role: "user" | "admin" }
declare module "fastify" {
  interface FastifyRequest { user: SessionUser | null; csrfToken: string | null }
}

const sha256 = (value: string) => createHash("sha256").update(value).digest();
const cookieOptions = {
  path: "/",
  httpOnly: true,
  secure: config.COOKIE_SECURE,
  sameSite: "lax" as const
};

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
}
export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try { return await argon2.verify(hash, password); } catch { return false; }
}

export async function createSession(user: SessionUser, reply: FastifyReply): Promise<string> {
  const token = randomBytes(32).toString("base64url");
  const csrf = randomBytes(24).toString("base64url");
  const expiresAt = new Date(Date.now() + config.SESSION_TTL_HOURS * 3_600_000);
  await query(
    "INSERT INTO forgeos_sessions(user_id, token_hash, csrf_token, expires_at) VALUES($1,$2,$3,$4)",
    [user.id, sha256(token), csrf, expiresAt]
  );
  reply.setCookie(config.SESSION_COOKIE_NAME, token, { ...cookieOptions, expires: expiresAt });
  return csrf;
}

export async function loadSession(request: FastifyRequest): Promise<void> {
  request.user = null;
  request.csrfToken = null;
  const token = request.cookies[config.SESSION_COOKIE_NAME];
  if (!token || token.length > 128) return;
  const result = await query<SessionUser & { csrf_token: string; expires_at: Date }>(
    `SELECT u.id, u.email, u.role, s.csrf_token, s.expires_at
       FROM forgeos_sessions s JOIN forgeos_users u ON u.id=s.user_id
      WHERE s.token_hash=$1 AND s.expires_at > now()`,
    [sha256(token)]
  );
  const row = result.rows[0];
  if (row) {
    request.user = { id: row.id, email: row.email, role: row.role };
    request.csrfToken = row.csrf_token;
  }
}

export function requireUser(request: FastifyRequest, reply: FastifyReply): boolean {
  if (!request.user) { void reply.code(401).send({ error: "authentication_required" }); return false; }
  return true;
}
export function requireAdmin(request: FastifyRequest, reply: FastifyReply): boolean {
  if (!requireUser(request, reply)) return false;
  if (request.user?.role !== "admin") { void reply.code(403).send({ error: "admin_required" }); return false; }
  return true;
}
export function requireCsrf(request: FastifyRequest, reply: FastifyReply): boolean {
  const supplied = request.headers["x-csrf-token"];
  if (typeof supplied !== "string" || !request.csrfToken || supplied !== request.csrfToken) {
    void reply.code(403).send({ error: "csrf_validation_failed" });
    return false;
  }
  return true;
}
export async function destroySession(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const token = request.cookies[config.SESSION_COOKIE_NAME];
  if (token) await query("DELETE FROM forgeos_sessions WHERE token_hash=$1", [sha256(token)]);
  reply.clearCookie(config.SESSION_COOKIE_NAME, cookieOptions);
}
