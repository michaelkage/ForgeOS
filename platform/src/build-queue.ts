import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { pool, query } from "./db.js";
import { config } from "./config.js";
import { requireCsrf, requireUser } from "./security.js";

const workerClaimSchema = z.object({
  workerId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/),
  leaseSeconds: z.number().int().min(30).max(900).default(180),
  architectures: z.array(z.enum(["arm64", "arm", "x86_64"])).min(1).max(3),
  romBases: z.array(z.enum(["lineage", "crdroid"])).min(1).max(2)
}).strict();
const leaseSchema = z.object({
  workerId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/),
  leaseToken: z.string().uuid()
}).strict();
const heartbeatSchema = leaseSchema.extend({ leaseSeconds: z.number().int().min(30).max(900).default(180) }).strict();
const failureSchema = leaseSchema.extend({
  errorCode: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/),
  retryable: z.boolean().default(true),
  message: z.string().trim().min(1).max(1000)
}).strict();
export const buildArtifactSchema = z.object({
    objectKey: z.string().min(3).max(512).regex(/^[A-Za-z0-9][A-Za-z0-9/_-]*$/).refine(value => value.split("/").every(segment => segment.length > 0 && segment !== "." && segment !== "..")),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    sizeBytes: z.number().int().positive().max(20 * 1024 * 1024 * 1024),
    contentType: z.literal("application/zip")
}).strict();
const completionSchema = leaseSchema.extend({ artifact: buildArtifactSchema }).strict();
const MAX_ACTIVE_BUILD_JOBS_PER_USER = 2;

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new TypeError("Non-finite number in build snapshot");
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError("Unable to serialize build snapshot value");
    return encoded;
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return "{" + keys.map(key => JSON.stringify(key) + ":" + canonicalJson(record[key])).join(",") + "}";
  }
  throw new TypeError("Build snapshot must contain JSON values only");
}

export function verifyBuildSnapshot(snapshot: unknown, expectedSha256: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(expectedSha256)) return false;
  const actual = createHash("sha256").update(canonicalJson(snapshot)).digest("hex");
  const actualBytes = Buffer.from(actual, "hex");
  const expectedBytes = Buffer.from(expectedSha256, "hex");
  return timingSafeEqual(actualBytes, expectedBytes);
}

function workerAuthorized(request: FastifyRequest, reply: FastifyReply): boolean {
  const expected = config.BUILD_WORKER_SHARED_SECRET;
  const header = request.headers.authorization;
  if (!config.ENABLE_ANDROID_BUILDS || !expected || typeof header !== "string" || !header.startsWith("Bearer ")) {
    void reply.code(503).send({ error: "build_workers_not_enabled" });
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

export async function registerBuildRoutes(app: FastifyInstance): Promise<void> {
  app.post("/api/configurations/:id/queue", async (request, reply) => {
    if (!requireUser(request, reply) || !requireCsrf(request, reply)) return;
    if (!config.ENABLE_ANDROID_BUILDS) return reply.code(503).send({ error: "android_build_submission_disabled" });
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    if (!id.success) return reply.code(400).send({ error: "invalid_configuration_id" });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const selected = await client.query(
        `SELECT c.id,c.user_id,c.name,c.rom_base,c.root_method,c.manifest_revision,c.options,c.updated_at,c.validation_report,
          d.codename,d.manufacturer,d.model,d.architecture,b.manifest_path,b.branch_name,
          s.repository_url,s.branch_name AS source_branch,s.source_path,s.verified_commit_sha
         FROM forgeos_rom_configurations c
         JOIN forgeos_devices d ON d.id=c.device_id
         JOIN forgeos_device_rom_bases b ON b.device_id=d.id AND b.rom_base=c.rom_base
         JOIN forgeos_device_sources s ON s.device_id=d.id AND s.rom_base=c.rom_base
           AND s.source_kind='device' AND s.verification_status='verified'
           AND s.verified_commit_sha = c.validation_report->'deviceTreeSource'->>'commitSha'
         WHERE c.id=$1 AND c.user_id=$2 AND c.status IN ('validated','queued')
           AND d.enabled=true AND b.enabled=true
         ORDER BY s.last_checked_at DESC NULLS LAST LIMIT 1 FOR UPDATE OF c`,
        [id.data, request.user!.id]
      );
      const row = selected.rows[0];
      if (!row || (row.validation_report as { valid?: boolean } | null)?.valid !== true) {
        await client.query("ROLLBACK");
        return reply.code(422).send({ error: "configuration_must_be_validated" });
      }
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [request.user!.id]);
      const existing = await client.query(
        "SELECT id,status,created_at FROM forgeos_build_jobs WHERE configuration_id=$1 AND status IN ('pending','leased')",
        [id.data]
      );
      if (existing.rowCount) {
        await client.query("COMMIT");
        return reply.code(202).send({ job: existing.rows[0] });
      }
      const active = await client.query(
        "SELECT count(*)::int AS count FROM forgeos_build_jobs WHERE user_id=$1 AND status IN ('pending','leased')",
        [request.user!.id]
      );
      if (active.rows[0]!.count >= MAX_ACTIVE_BUILD_JOBS_PER_USER) {
        await client.query("ROLLBACK");
        return reply.code(429).send({ error: "active_build_job_limit_reached", limit: MAX_ACTIVE_BUILD_JOBS_PER_USER });
      }
      const snapshot = {
        schemaVersion: 1,
        configuration: {
          id: row.id, name: row.name, romBase: row.rom_base, rootMethod: row.root_method,
          manifestRevision: row.manifest_revision, options: row.options
        },
        device: { codename: row.codename, manufacturer: row.manufacturer, model: row.model, architecture: row.architecture },
        manifest: { path: row.manifest_path, branch: row.branch_name },
        deviceTree: {
          repositoryUrl: row.repository_url, branch: row.source_branch,
          sourcePath: row.source_path, commitSha: row.verified_commit_sha
        },
        validationReport: row.validation_report,
        configurationUpdatedAt: row.updated_at
      };
      const fingerprint = createHash("sha256").update(canonicalJson(snapshot)).digest("hex");
      const inserted = await client.query(
        `INSERT INTO forgeos_build_jobs(user_id,configuration_id,snapshot,snapshot_sha256)
         VALUES($1,$2,$3,$4)
         ON CONFLICT (configuration_id) WHERE status IN ('pending','leased')
         DO UPDATE SET updated_at=forgeos_build_jobs.updated_at
         RETURNING id,status,created_at`,
        [request.user!.id, id.data, snapshot, fingerprint]
      );
      await client.query("UPDATE forgeos_rom_configurations SET status='queued' WHERE id=$1", [id.data]);
      await client.query("COMMIT");
      return reply.code(202).send({ job: inserted.rows[0] });
    } catch (error) {
      await client.query("ROLLBACK");
      request.log.error(error);
      return reply.code(500).send({ error: "build_job_enqueue_failed" });
    } finally {
      client.release();
    }
  });

  app.get("/api/builds/status", async () => ({
    submissionEnabled: config.ENABLE_ANDROID_BUILDS,
    reason: config.ENABLE_ANDROID_BUILDS ? null : "Build execution is disabled by the operator."
  }));

  app.get("/api/build-jobs", async (request, reply) => {
    if (!requireUser(request, reply)) return;
    const result = await query(
      `SELECT id,configuration_id,status,attempts,max_attempts,error_code,error_message,
        artifact_sha256,artifact_size_bytes,created_at,started_at,completed_at,updated_at
       FROM forgeos_build_jobs WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
      [request.user!.id]
    );
    return { jobs: result.rows };
  });

  app.get("/api/build-jobs/:id", async (request, reply) => {
    if (!requireUser(request, reply)) return;
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    if (!id.success) return reply.code(400).send({ error: "invalid_build_job_id" });
    const result = await query(
      `SELECT id,configuration_id,status,attempts,max_attempts,error_code,error_message,
        artifact_sha256,artifact_size_bytes,created_at,started_at,completed_at,updated_at
       FROM forgeos_build_jobs WHERE id=$1 AND user_id=$2`,
      [id.data, request.user!.id]
    );
    if (!result.rowCount) return reply.code(404).send({ error: "build_job_not_found" });
    return { job: result.rows[0] };
  });

  app.post("/api/build-jobs/:id/cancel", async (request, reply) => {
    if (!requireUser(request, reply) || !requireCsrf(request, reply)) return;
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    if (!id.success) return reply.code(400).send({ error: "invalid_build_job_id" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `UPDATE forgeos_build_jobs SET status='cancelled',lease_token=NULL,lease_expires_at=NULL,
          worker_id=NULL,completed_at=now(),updated_at=now()
         WHERE id=$1 AND user_id=$2 AND status IN ('pending','leased')
         RETURNING id,status,configuration_id`,
        [id.data, request.user!.id]
      );
      if (!result.rowCount) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "build_job_not_cancellable" });
      }
      await client.query("UPDATE forgeos_rom_configurations SET status='draft' WHERE id=$1 AND status='queued'", [result.rows[0]!.configuration_id]);
      await client.query("COMMIT");
      return { job: result.rows[0] };
    } catch (error) {
      await client.query("ROLLBACK");
      request.log.error(error);
      return reply.code(500).send({ error: "build_job_cancellation_failed" });
    } finally {
      client.release();
    }
  });

  app.post("/api/internal/build-jobs/claim", async (request, reply) => {
    if (!workerAuthorized(request, reply)) return;
    const parsed = workerClaimSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_worker_claim" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `WITH expired AS (
          UPDATE forgeos_build_jobs SET status=CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,
            worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
            error_code=CASE WHEN attempts >= max_attempts THEN 'worker_lease_expired' ELSE error_code END,
            error_message=CASE WHEN attempts >= max_attempts THEN 'Worker lease expired too many times' ELSE error_message END,
            completed_at=CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END,
            updated_at=now()
          WHERE status='leased' AND lease_expires_at < now()
          RETURNING configuration_id,status,error_code
        )
        UPDATE forgeos_rom_configurations c SET status='draft'
        FROM expired e WHERE c.id=e.configuration_id AND c.status='queued'
          AND e.status='failed' AND e.error_code='worker_lease_expired'`
      );
      const claimed = await client.query(
        `WITH candidate AS (
          SELECT id FROM forgeos_build_jobs WHERE status='pending' AND attempts < max_attempts
            AND snapshot->'device'->>'architecture'=ANY($4::text[])
            AND snapshot->'configuration'->>'romBase'=ANY($5::text[])
          ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
        )
        UPDATE forgeos_build_jobs j SET status='leased',worker_id=$1,lease_token=$2,
          lease_expires_at=now()+($3::text || ' seconds')::interval,
          attempts=attempts+1,started_at=COALESCE(started_at,now()),updated_at=now()
        FROM candidate WHERE j.id=candidate.id
        RETURNING j.id,j.snapshot,j.snapshot_sha256,j.attempts,j.max_attempts,j.lease_token,j.lease_expires_at`,
        [parsed.data.workerId, randomUUID(), parsed.data.leaseSeconds, parsed.data.architectures, parsed.data.romBases]
      );
      if (claimed.rows[0] && !verifyBuildSnapshot(claimed.rows[0].snapshot, claimed.rows[0].snapshot_sha256)) {
        throw new Error("Stored build snapshot fingerprint mismatch");
      }
      await client.query("COMMIT");
      return { job: claimed.rows[0] ?? null };
    } catch (error) {
      await client.query("ROLLBACK");
      request.log.error(error);
      return reply.code(500).send({ error: "worker_claim_failed" });
    } finally {
      client.release();
    }
  });

  app.post("/api/internal/build-jobs/:id/heartbeat", async (request, reply) => {
    if (!workerAuthorized(request, reply)) return;
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    const parsed = heartbeatSchema.safeParse(request.body);
    if (!id.success || !parsed.success) return reply.code(400).send({ error: "invalid_heartbeat" });
    const result = await query(
      `UPDATE forgeos_build_jobs SET lease_expires_at=now()+($4::text || ' seconds')::interval,updated_at=now()
       WHERE id=$1 AND status='leased' AND worker_id=$2 AND lease_token=$3 AND lease_expires_at > now()
       RETURNING id,lease_expires_at`,
      [id.data, parsed.data.workerId, parsed.data.leaseToken, parsed.data.leaseSeconds]
    );
    if (!result.rowCount) return reply.code(409).send({ error: "worker_lease_lost" });
    return { job: result.rows[0] };
  });

  app.post("/api/internal/build-jobs/:id/complete", async (request, reply) => {
    if (!workerAuthorized(request, reply)) return;
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    const parsed = completionSchema.safeParse(request.body);
    if (!id.success || !parsed.success) return reply.code(400).send({ error: "invalid_build_completion" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `UPDATE forgeos_build_jobs SET status='succeeded',artifact_object_key=$4,artifact_sha256=$5,
          artifact_size_bytes=$6,artifact_content_type=$7,completed_at=now(),updated_at=now(),
          lease_token=NULL,lease_expires_at=NULL,worker_id=NULL
         WHERE id=$1 AND status='leased' AND worker_id=$2 AND lease_token=$3 AND lease_expires_at > now()
         RETURNING id,configuration_id,status,artifact_sha256,artifact_size_bytes,completed_at`,
        [id.data, parsed.data.workerId, parsed.data.leaseToken, parsed.data.artifact.objectKey,
          parsed.data.artifact.sha256, parsed.data.artifact.sizeBytes, parsed.data.artifact.contentType]
      );
      if (!result.rowCount) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "worker_lease_lost" });
      }
      await client.query("UPDATE forgeos_rom_configurations SET status='validated' WHERE id=$1 AND status='queued'", [result.rows[0]!.configuration_id]);
      await client.query("COMMIT");
      return { job: result.rows[0] };
    } catch (error) {
      await client.query("ROLLBACK");
      request.log.error(error);
      return reply.code(500).send({ error: "build_completion_failed" });
    } finally {
      client.release();
    }
  });

  app.post("/api/internal/build-jobs/:id/fail", async (request, reply) => {
    if (!workerAuthorized(request, reply)) return;
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    const parsed = failureSchema.safeParse(request.body);
    if (!id.success || !parsed.success) return reply.code(400).send({ error: "invalid_build_failure" });
    const result = await query(
      `UPDATE forgeos_build_jobs SET
        status=CASE WHEN $4::boolean AND attempts < max_attempts THEN 'pending' ELSE 'failed' END,
        error_code=$5,error_message=$6,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
        completed_at=CASE WHEN NOT ($4::boolean AND attempts < max_attempts) THEN now() ELSE NULL END,
        updated_at=now()
       WHERE id=$1 AND status='leased' AND worker_id=$2 AND lease_token=$3 AND lease_expires_at > now()
       RETURNING id,status,attempts,max_attempts`,
      [id.data, parsed.data.workerId, parsed.data.leaseToken, parsed.data.retryable,
        parsed.data.errorCode, parsed.data.message]
    );
    if (!result.rowCount) return reply.code(409).send({ error: "worker_lease_lost" });
    if (result.rows[0]!.status === "failed") {
      await query("UPDATE forgeos_rom_configurations SET status='draft' WHERE id=(SELECT configuration_id FROM forgeos_build_jobs WHERE id=$1) AND status='queued'", [id.data]);
    }
    return { job: result.rows[0] };
  });
}
