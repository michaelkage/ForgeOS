import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { pool } from "./db.js";
import { config } from "./config.js";

const issueSchema = z.object({
  jobId: z.string().uuid(),
  workerId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/),
  leaseToken: z.string().uuid()
}).strict();

export function hashBootstrapCredential(credential: string): string {
  return createHash("sha256").update(credential, "utf8").digest("hex");
}

export function createBootstrapCredential(): { credential: string; sha256: string } {
  const credential = randomBytes(32).toString("base64url");
  return { credential, sha256: hashBootstrapCredential(credential) };
}

function internalWorkerAuthorized(request: FastifyRequest, reply: FastifyReply): boolean {
  const expected = config.BUILD_WORKER_SHARED_SECRET;
  const header = request.headers.authorization;
  if (!config.ENABLE_ANDROID_BUILDS || !expected) {
    void reply.code(503).send({ error: "build_workers_not_enabled" });
    return false;
  }
  if (typeof header !== "string" || !header.startsWith("Bearer ")) {
    void reply.code(401).send({ error: "worker_authentication_failed" });
    return false;
  }
  const supplied = Buffer.from(header.slice(7), "utf8");
  const known = Buffer.from(expected, "utf8");
  if (supplied.length !== known.length || !timingSafeEqual(supplied, known)) {
    void reply.code(401).send({ error: "worker_authentication_failed" });
    return false;
  }
  return true;
}

/**
 * Issues a short-lived, one-use credential for a currently leased build attempt.
 * Only the SHA-256 digest is persisted; the raw credential is returned once.
 */
export async function registerGuestBootstrapRoutes(app: FastifyInstance): Promise<void> {
  app.post("/api/internal/guest-bootstrap/issue", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } }
  }, async (request, reply) => {
    if (!internalWorkerAuthorized(request, reply)) return;
    const parsed = issueSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_guest_bootstrap_issue" });
    const { jobId, workerId, leaseToken } = parsed.data;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const leased = await client.query<{ attempts: number }>(
        `SELECT attempts FROM forgeos_build_jobs
         WHERE id=$1 AND status='leased' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > now()
         FOR UPDATE`,
        [jobId, workerId, leaseToken]
      );
      if (!leased.rowCount) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "active_build_lease_not_found" });
      }
      const attempt = leased.rows[0]!.attempts;
      const generated = createBootstrapCredential();
      const inserted = await client.query<{ expires_at: Date }>(
        `INSERT INTO forgeos_guest_bootstrap_credentials
           (build_job_id,attempt,worker_id,credential_sha256,expires_at)
         VALUES($1,$2,$3,$4,now()+interval '3 minutes')
         ON CONFLICT (build_job_id,attempt) DO UPDATE
           SET worker_id=EXCLUDED.worker_id,
               credential_sha256=EXCLUDED.credential_sha256,
               expires_at=EXCLUDED.expires_at,
               created_at=now()
         WHERE forgeos_guest_bootstrap_credentials.redeemed_at IS NULL
           AND forgeos_guest_bootstrap_credentials.expires_at <= now()
         RETURNING expires_at`,
        [jobId, attempt, workerId, generated.sha256]
      );
      if (!inserted.rowCount) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "guest_bootstrap_credential_unavailable" });
      }
      await client.query("COMMIT");
      return reply.code(201).send({
        credential: generated.credential,
        jobId,
        attempt,
        expiresAt: inserted.rows[0]!.expires_at
      });
    } catch (error) {
      await client.query("ROLLBACK");
      request.log.error(error);
      return reply.code(500).send({ error: "guest_bootstrap_issue_failed" });
    } finally {
      client.release();
    }
  });

  // The guest presents the credential as a bearer token. Redemption atomically marks
  // it consumed, so neither concurrent requests nor later re-issuance can reuse it.
  app.post("/api/internal/guest-bootstrap/redeem", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } }
  }, async (request, reply) => {
    const header = request.headers.authorization;
    if (typeof header !== "string" || !/^Bearer [A-Za-z0-9_-]{40,64}$/.test(header)) {
      return reply.code(401).send({ error: "guest_bootstrap_authentication_failed" });
    }
    const credential = header.slice(7);
    const digest = hashBootstrapCredential(credential);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const consumed = await client.query<{ build_job_id: string; attempt: number; worker_id: string }>(
        `UPDATE forgeos_guest_bootstrap_credentials SET redeemed_at=now()
         WHERE credential_sha256=$1 AND expires_at > now() AND redeemed_at IS NULL
         RETURNING build_job_id,attempt,worker_id`,
        [digest]
      );
      if (!consumed.rowCount) {
        await client.query("ROLLBACK");
        return reply.code(401).send({ error: "guest_bootstrap_authentication_failed" });
      }
      const credentialRow = consumed.rows[0]!;
      const job = await client.query<{
        snapshot: unknown; snapshot_sha256: string; lease_token: string;
      }>(
        `SELECT snapshot,snapshot_sha256,lease_token
         FROM forgeos_build_jobs
         WHERE id=$1 AND status='leased' AND attempts=$2 AND worker_id=$3
           AND lease_expires_at > now()
         FOR UPDATE`,
        [credentialRow.build_job_id, credentialRow.attempt, credentialRow.worker_id]
      );
      if (!job.rowCount) {
        await client.query("COMMIT");
        return reply.code(401).send({ error: "guest_bootstrap_authentication_failed" });
      }
      await client.query("COMMIT");
      return {
        jobId: credentialRow.build_job_id,
        attempt: credentialRow.attempt,
        workerId: credentialRow.worker_id,
        leaseToken: job.rows[0]!.lease_token,
        snapshot: job.rows[0]!.snapshot,
        snapshotSha256: job.rows[0]!.snapshot_sha256
      };
    } catch (error) {
      await client.query("ROLLBACK");
      request.log.error(error);
      return reply.code(500).send({ error: "guest_bootstrap_redemption_failed" });
    } finally {
      client.release();
    }
  });
}
