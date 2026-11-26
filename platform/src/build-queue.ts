import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { pool, query } from "./db.js";
import { config } from "./config.js";
import { requireCsrf, requireUser } from "./security.js";
import { validateRepositoryManifest } from "./manifest.js";
import { createArtifactDownloadUrl, createArtifactUploadUrl, verifyUploadedArtifact } from "./artifact-storage.js";
import { signUploadedArtifact } from "./signing-service.js";

export const workerClaimSchema = z.object({
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
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    sizeBytes: z.number().int().positive().max(20 * 1024 * 1024 * 1024),
    contentType: z.literal("application/zip")
}).strict();
export const sourceLockfileSchema = z.object({
  schemaVersion: z.literal(1),
  projects: z.array(z.object({
    path: z.string().min(1).max(512).refine(value => !value.startsWith("/") && !/[\x00-\x1f\x7f\\]/.test(value) && value.split("/").every(part => part.length > 0 && part !== "." && part !== "..")),
    name: z.string().min(1).max(512).refine(value => !/[\x00-\x1f\x7f]/.test(value)),
    revision: z.string().regex(/^[a-f0-9]{40}$/)
  }).strict()).min(1).max(2000)
}).strict().superRefine((lockfile, ctx) => {
  const paths = lockfile.projects.map(project => project.path);
  if (new Set(paths).size !== paths.length) ctx.addIssue({ code: "custom", message: "Source lockfile paths must be unique", path: ["projects"] });
  for (let i = 1; i < paths.length; i++) {
    if (paths[i - 1]! >= paths[i]!) ctx.addIssue({ code: "custom", message: "Source lockfile projects must be sorted by path", path: ["projects", i, "path"] });
  }
});
const completionSchema = leaseSchema.extend({
  artifact: buildArtifactSchema,
  sourceLockfile: sourceLockfileSchema,
  sourceLockfileSha256: z.string().regex(/^[a-f0-9]{64}$/)
}).strict();
const uploadIntentSchema = leaseSchema.extend({
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  sizeBytes: z.number().int().positive().max(20 * 1024 * 1024 * 1024)
}).strict();
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

export function isWorkerLeaseCredentialValid(header: string | undefined, leaseToken: string): boolean {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(header.slice(7), "utf8");
  const expected = Buffer.from(leaseToken, "utf8");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function workerLeaseAuthorized(request: FastifyRequest, reply: FastifyReply, leaseToken: string): boolean {
  if (!config.ENABLE_ANDROID_BUILDS || !config.BUILD_WORKER_SHARED_SECRET) {
    void reply.code(503).send({ error: "build_workers_not_enabled" });
    return false;
  }
  if (!isWorkerLeaseCredentialValid(request.headers.authorization, leaseToken)) {
    void reply.code(401).send({ error: "worker_lease_authentication_failed" });
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
          d.id AS device_id,d.codename,d.manufacturer,d.model,d.architecture,b.manifest_path,b.branch_name,
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
      const pinnedManifest = await validateRepositoryManifest(config.MANIFEST_ROOT, row.manifest_path);
      const validatedManifestSha = (row.validation_report as { manifestSha256?: string }).manifestSha256;
      if (!pinnedManifest.ok || !pinnedManifest.content || !pinnedManifest.sha256 || pinnedManifest.sha256 !== validatedManifestSha) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "manifest_changed_revalidate_configuration" });
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
      const sourceInputs = await client.query(
        `SELECT source_kind,rom_base,repository_url,branch_name,source_path,verified_commit_sha
         FROM forgeos_device_sources
         WHERE device_id=$1 AND verification_status='verified'
           AND (rom_base IS NULL OR rom_base=$2)
         ORDER BY source_kind,rom_base NULLS FIRST,repository_url,branch_name`,
        [row.device_id, row.rom_base]
      );
      const snapshot = {
        schemaVersion: 1,
        configuration: {
          id: row.id, name: row.name, romBase: row.rom_base, rootMethod: row.root_method,
          manifestRevision: row.manifest_revision, options: row.options
        },
        device: { id: row.device_id, codename: row.codename, manufacturer: row.manufacturer, model: row.model, architecture: row.architecture },
        manifest: { path: row.manifest_path, branch: row.branch_name, sha256: pinnedManifest.sha256, content: pinnedManifest.content },
        deviceTree: {
          repositoryUrl: row.repository_url, branch: row.source_branch,
          sourcePath: row.source_path, commitSha: row.verified_commit_sha
        },
        sourceInputs: sourceInputs.rows.map(source => ({
          sourceKind: source.source_kind, romBase: source.rom_base,
          repositoryUrl: source.repository_url, branch: source.branch_name,
          sourcePath: source.source_path, commitSha: source.verified_commit_sha
        })),
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
      await client.query(
        "INSERT INTO forgeos_build_job_events(build_job_id,attempt,event_type,details) VALUES($1,0,'queued',$2)",
        [inserted.rows[0]!.id, JSON.stringify({ snapshotSha256: fingerprint })]
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
        snapshot_sha256,snapshot->'configuration'->>'name' AS configuration_name,
        snapshot->'device'->>'codename' AS device_codename,
        snapshot->'configuration'->>'romBase' AS rom_base,
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
        snapshot_sha256,snapshot->'configuration'->>'name' AS configuration_name,
        snapshot->'device'->>'codename' AS device_codename,
        snapshot->'configuration'->>'romBase' AS rom_base,
        artifact_sha256,artifact_size_bytes,created_at,started_at,completed_at,updated_at
       FROM forgeos_build_jobs WHERE id=$1 AND user_id=$2`,
      [id.data, request.user!.id]
    );
    if (!result.rowCount) return reply.code(404).send({ error: "build_job_not_found" });
    return { job: result.rows[0] };
  });

  app.get("/api/build-jobs/:id/events", async (request, reply) => {
    if (!requireUser(request, reply)) return;
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    const queryParams = request.query as { after?: string };
    const after = queryParams.after === undefined ? null : /^[0-9]{1,18}$/.test(queryParams.after) ? queryParams.after : undefined;
    if (!id.success || after === undefined) return reply.code(400).send({ error: "invalid_build_event_cursor" });
    const owned = await query("SELECT 1 FROM forgeos_build_jobs WHERE id=$1 AND user_id=$2", [id.data, request.user!.id]);
    if (!owned.rowCount) return reply.code(404).send({ error: "build_job_not_found" });
    const result = await query(
      `SELECT id,attempt,worker_id,event_type,details,created_at
       FROM forgeos_build_job_events
       WHERE build_job_id=$1 AND ($2::bigint IS NULL OR id>$2)
       ORDER BY id ASC LIMIT 100`,
      [id.data, after]
    );
    const events = result.rows;
    return { events, nextCursor: events.length ? String(events[events.length - 1]!.id) : after };
  });

  app.post("/api/build-jobs/:id/download", async (request, reply) => {
    if (!requireUser(request, reply) || !requireCsrf(request, reply)) return;
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    if (!id.success) return reply.code(400).send({ error: "invalid_build_job_id" });
    const result = await query<{ artifact_object_key: string }>(
      "SELECT artifact_object_key FROM forgeos_build_jobs WHERE id=$1 AND user_id=$2 AND status='succeeded' AND artifact_verified_at IS NOT NULL AND artifact_object_key IS NOT NULL",
      [id.data, request.user!.id]
    );
    if (!result.rowCount) return reply.code(404).send({ error: "verified_build_artifact_not_found" });
    try {
      return { url: createArtifactDownloadUrl(result.rows[0]!.artifact_object_key, 300), expiresInSeconds: 300 };
    } catch (error) {
      request.log.error(error);
      return reply.code(503).send({ error: "artifact_storage_unavailable" });
    }
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
         RETURNING id,status,configuration_id,attempts`,
        [id.data, request.user!.id]
      );
      if (!result.rowCount) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "build_job_not_cancellable" });
      }
      await client.query(
        "INSERT INTO forgeos_build_job_events(build_job_id,attempt,event_type,details) VALUES($1,$2,'cancelled',$3)",
        [result.rows[0]!.id, result.rows[0]!.attempts, JSON.stringify({ previousStatus: "pending_or_leased" })]
      );
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
        `WITH stale AS (
          UPDATE forgeos_build_jobs j SET status='failed',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
            error_code='source_provenance_invalidated',
            error_message='Device or verified source provenance changed after this job was queued',
            completed_at=now(),updated_at=now()
          WHERE j.status IN ('pending','leased')
            AND NOT EXISTS (
              SELECT 1
              FROM forgeos_devices d
              JOIN forgeos_device_rom_bases b ON b.device_id=d.id
                AND b.rom_base=(j.snapshot->'configuration'->>'romBase')::forgeos_rom_base
                AND b.enabled=true
              JOIN forgeos_device_sources s ON s.device_id=d.id
                AND s.source_kind='device'
                AND s.rom_base=b.rom_base
                AND s.verification_status='verified'
                AND s.verified_commit_sha=j.snapshot->'deviceTree'->>'commitSha'
              WHERE d.id=(j.snapshot->'device'->>'id')::uuid AND d.enabled=true
            )
            AND NOT EXISTS (
              SELECT 1
              FROM jsonb_array_elements(j.snapshot->'sourceInputs') AS inputs(source)
              WHERE NOT EXISTS (
                SELECT 1 FROM forgeos_device_sources ds
                WHERE ds.device_id=(j.snapshot->'device'->>'id')::uuid
                  AND ds.source_kind=(inputs.source->>'sourceKind')::forgeos_device_source_kind
                  AND ds.rom_base IS NOT DISTINCT FROM NULLIF(inputs.source->>'romBase','')::forgeos_rom_base
                  AND ds.repository_url=inputs.source->>'repositoryUrl'
                  AND ds.branch_name=inputs.source->>'branch'
                  AND ds.source_path=inputs.source->>'sourcePath'
                  AND ds.verified_commit_sha=inputs.source->>'commitSha'
                  AND ds.verification_status='verified'
              )
            )
          RETURNING configuration_id
        )
        UPDATE forgeos_rom_configurations c SET status='draft'
        FROM stale s WHERE c.id=s.configuration_id AND c.status='queued'`
      );
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
          ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED
        )
        UPDATE forgeos_build_jobs j SET status='leased',worker_id=$1,lease_token=$2,
          lease_expires_at=now()+($3::text || ' seconds')::interval,
          attempts=attempts+1,started_at=COALESCE(started_at,now()),updated_at=now()
        FROM candidate WHERE j.id=candidate.id
        RETURNING j.id,j.snapshot,j.snapshot_sha256 AS "snapshotSha256",j.attempts,j.max_attempts AS "maxAttempts",j.lease_token AS "leaseToken",j.lease_expires_at AS "leaseExpiresAt"`,
        [parsed.data.workerId, randomUUID(), parsed.data.leaseSeconds, parsed.data.architectures, parsed.data.romBases]
      );
      if (claimed.rows[0] && !verifyBuildSnapshot(claimed.rows[0].snapshot, claimed.rows[0].snapshot_sha256)) {
        throw new Error("Stored build snapshot fingerprint mismatch");
      }
      if (claimed.rows[0]) {
        await client.query(
          "INSERT INTO forgeos_build_job_events(build_job_id,attempt,worker_id,event_type,details) VALUES($1,$2,$3,'claimed',$4)",
          [claimed.rows[0].id, claimed.rows[0].attempts, parsed.data.workerId, JSON.stringify({ leaseExpiresAt: claimed.rows[0].lease_expires_at })]
        );
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

  app.get("/api/internal/build-jobs/:id/status", async (request, reply) => {
    if (!workerAuthorized(request, reply)) return;
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    if (!id.success) return reply.code(400).send({ error: "invalid_build_job_id" });
    const result = await query(
      `SELECT id,status,attempts,worker_id AS "workerId",lease_expires_at AS "leaseExpiresAt"
       FROM forgeos_build_jobs WHERE id=$1`,
      [id.data]
    );
    if (!result.rowCount) return reply.code(404).send({ error: "build_job_not_found" });
    return { job: result.rows[0] };
  });

  app.post("/api/internal/build-jobs/:id/heartbeat", async (request, reply) => {
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    const parsed = heartbeatSchema.safeParse(request.body);
    if (!id.success || !parsed.success) return reply.code(400).send({ error: "invalid_heartbeat" });
    if (!workerLeaseAuthorized(request, reply, parsed.data.leaseToken)) return;
    const result = await query(
      `UPDATE forgeos_build_jobs SET lease_expires_at=now()+($4::text || ' seconds')::interval,updated_at=now()
       WHERE id=$1 AND status='leased' AND worker_id=$2 AND lease_token=$3 AND lease_expires_at > now()
       RETURNING id,lease_expires_at`,
      [id.data, parsed.data.workerId, parsed.data.leaseToken, parsed.data.leaseSeconds]
    );
    if (!result.rowCount) return reply.code(409).send({ error: "worker_lease_lost" });
    return { job: result.rows[0] };
  });

  app.post("/api/internal/build-jobs/:id/artifact-upload", async (request, reply) => {
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    const parsed = uploadIntentSchema.safeParse(request.body);
    if (!id.success || !parsed.success) return reply.code(400).send({ error: "invalid_artifact_upload_intent" });
    if (!workerLeaseAuthorized(request, reply, parsed.data.leaseToken)) return;
    try {
      const lease = await query<{ user_id: string; attempts: number }>(
        "SELECT user_id,attempts FROM forgeos_build_jobs WHERE id=$1 AND status='leased' AND worker_id=$2 AND lease_token=$3 AND lease_expires_at > now()",
        [id.data, parsed.data.workerId, parsed.data.leaseToken]
      );
      if (!lease.rowCount) return reply.code(409).send({ error: "worker_lease_lost" });
      const existing = await query<{ object_key: string; expected_sha256: string; expected_size_bytes: string; expires_at: Date }>(
        "SELECT object_key,expected_sha256,expected_size_bytes,expires_at FROM forgeos_artifact_upload_intents WHERE build_job_id=$1 AND lease_token=$2",
        [id.data, parsed.data.leaseToken]
      );
      let objectKey: string, expiresAt: Date;
      if (existing.rowCount) {
        const intent = existing.rows[0]!;
        if (intent.expected_sha256 !== parsed.data.sha256 || Number(intent.expected_size_bytes) !== parsed.data.sizeBytes || intent.expires_at.getTime() <= Date.now()) {
          return reply.code(409).send({ error: "artifact_upload_intent_conflict" });
        }
        objectKey = intent.object_key;
        expiresAt = intent.expires_at;
      } else {
        objectKey = "artifacts/" + lease.rows[0]!.user_id + "/" + id.data + "/" + lease.rows[0]!.attempts + "/" + randomUUID() + ".zip";
        const inserted = await query<{ expires_at: Date; object_key: string; expected_sha256: string; expected_size_bytes: string }>(
          `INSERT INTO forgeos_artifact_upload_intents(build_job_id,worker_id,lease_token,object_key,expected_sha256,expected_size_bytes,expires_at)
           VALUES($1,$2,$3,$4,$5,$6,now()+interval '10 minutes')
           ON CONFLICT (build_job_id,lease_token) DO UPDATE SET object_key=forgeos_artifact_upload_intents.object_key
           RETURNING expires_at,object_key,expected_sha256,expected_size_bytes`,
          [id.data, parsed.data.workerId, parsed.data.leaseToken, objectKey, parsed.data.sha256, parsed.data.sizeBytes]
        );
        const saved = inserted.rows[0]!;
        if (saved.expected_sha256 !== parsed.data.sha256 || Number(saved.expected_size_bytes) !== parsed.data.sizeBytes || saved.expires_at.getTime() <= Date.now()) {
          return reply.code(409).send({ error: "artifact_upload_intent_conflict" });
        }
        objectKey = saved.object_key;
        expiresAt = saved.expires_at;
      }
      await query(
        "INSERT INTO forgeos_build_job_events(build_job_id,attempt,worker_id,event_type,details) SELECT $1,attempts,$2,'artifact_upload_authorized',$3 FROM forgeos_build_jobs WHERE id=$1",
        [id.data, parsed.data.workerId, JSON.stringify({ sha256: parsed.data.sha256, sizeBytes: parsed.data.sizeBytes })]
      );
      return {
        objectKey,
        method: "PUT",
        url: createArtifactUploadUrl(objectKey, parsed.data.sizeBytes, Math.max(1, Math.min(600, Math.floor((expiresAt.getTime() - Date.now()) / 1000)))),
        requiredHeaders: { "content-type": "application/zip", "content-length": String(parsed.data.sizeBytes), "if-none-match": "*" },
        expiresAt
      };
    } catch (error) {
      request.log.error(error);
      return reply.code(503).send({ error: "artifact_storage_unavailable" });
    }
  });

  app.post("/api/internal/build-jobs/:id/complete", async (request, reply) => {
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    const parsed = completionSchema.safeParse(request.body);
    if (!id.success || !parsed.success) return reply.code(400).send({ error: "invalid_build_completion" });
    if (!workerLeaseAuthorized(request, reply, parsed.data.leaseToken)) return;
    const artifact = parsed.data.artifact;
    const sourceLockfileDigest = createHash("sha256").update(canonicalJson(parsed.data.sourceLockfile)).digest("hex");
    if (sourceLockfileDigest !== parsed.data.sourceLockfileSha256) {
      return reply.code(422).send({ error: "source_lockfile_digest_mismatch" });
    }
    try {
      const intent = await query<{ expected_sha256: string; expected_size_bytes: string; object_key: string; snapshot_sha256: string; attempts: number; user_id: string }>(
        `SELECT i.expected_sha256,i.expected_size_bytes,i.object_key,j.snapshot_sha256,j.attempts,j.user_id
         FROM forgeos_artifact_upload_intents i
         JOIN forgeos_build_jobs j ON j.id=i.build_job_id
         WHERE i.build_job_id=$1 AND i.worker_id=$2 AND i.lease_token=$3
           AND i.expires_at > now() AND i.verified_at IS NULL
           AND j.status='leased' AND j.worker_id=$2 AND j.lease_token=$3 AND j.lease_expires_at > now()`,
        [id.data, parsed.data.workerId, parsed.data.leaseToken]
      );
      if (!intent.rowCount) return reply.code(409).send({ error: "artifact_upload_intent_missing_or_expired" });
      if (intent.rows[0]!.expected_sha256 !== artifact.sha256 || Number(intent.rows[0]!.expected_size_bytes) !== artifact.sizeBytes || artifact.contentType !== "application/zip") {
        return reply.code(422).send({ error: "artifact_metadata_does_not_match_upload_intent" });
      }
      const inputObjectKey = intent.rows[0]!.object_key;
      await verifyUploadedArtifact(inputObjectKey, artifact.sizeBytes, artifact.sha256);
      const signedArtifact = await signUploadedArtifact({
        userId: intent.rows[0]!.user_id,
        jobId: id.data,
        attempt: intent.rows[0]!.attempts,
        snapshotSha256: intent.rows[0]!.snapshot_sha256,
        inputObjectKey,
        inputSha256: artifact.sha256,
        inputSizeBytes: artifact.sizeBytes
      });
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await client.query(
          `UPDATE forgeos_build_jobs SET status='succeeded',artifact_object_key=$4,artifact_sha256=$5,
            artifact_size_bytes=$6,artifact_content_type='application/zip',artifact_verified_at=now(),
            source_lockfile=$7::jsonb,source_lockfile_sha256=$8,
            completed_at=now(),updated_at=now(),lease_token=NULL,lease_expires_at=NULL,worker_id=NULL
           WHERE id=$1 AND status='leased' AND worker_id=$2 AND lease_token=$3 AND lease_expires_at > now()
           RETURNING id,configuration_id,status,attempts,artifact_sha256,artifact_size_bytes,artifact_verified_at,completed_at`,
          [id.data, parsed.data.workerId, parsed.data.leaseToken, signedArtifact.objectKey, signedArtifact.sha256, signedArtifact.sizeBytes, JSON.stringify(parsed.data.sourceLockfile), sourceLockfileDigest]
        );
        if (!result.rowCount) {
          await client.query("ROLLBACK");
          return reply.code(409).send({ error: "worker_lease_lost" });
        }
        await client.query(
          "INSERT INTO forgeos_build_job_events(build_job_id,attempt,worker_id,event_type,details) VALUES($1,$2,$3,'artifact_verified',$4)",
          [result.rows[0]!.id, result.rows[0]!.attempts, parsed.data.workerId, JSON.stringify({
            inputSha256: artifact.sha256, inputSizeBytes: artifact.sizeBytes,
            sha256: signedArtifact.sha256, sizeBytes: signedArtifact.sizeBytes, signed: true,
            sourceLockfileSha256: sourceLockfileDigest, sourceProjectCount: parsed.data.sourceLockfile.projects.length
          })]
        );
        await client.query("UPDATE forgeos_artifact_upload_intents SET verified_at=now() WHERE build_job_id=$1 AND lease_token=$2 AND verified_at IS NULL", [id.data, parsed.data.leaseToken]);
        await client.query("UPDATE forgeos_rom_configurations SET status='validated' WHERE id=$1 AND status='queued'", [result.rows[0]!.configuration_id]);
        await client.query("COMMIT");
        return { job: result.rows[0] };
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      request.log.error(error);
      if (error instanceof Error && error.message.startsWith("artifact_signing_rejected:")) {
        return reply.code(422).send({ error: "artifact_signing_rejected" });
      }
      if (error instanceof Error && error.message.startsWith("signed_artifact_verification_failed:")) {
        return reply.code(422).send({ error: "signed_artifact_verification_failed" });
      }
      if (error instanceof Error && error.message.startsWith("signing_service_unavailable:")) {
        return reply.code(503).send({ error: "artifact_signing_unavailable" });
      }
      if (error instanceof Error && /not present|size or content type|could not be read|exceeds its declared size|SHA-256 verification/.test(error.message)) {
        return reply.code(422).send({ error: "artifact_verification_failed" });
      }
      return reply.code(503).send({ error: "artifact_storage_unavailable" });
    }
  });

  app.post("/api/internal/build-jobs/:id/fail", async (request, reply) => {
    const id = z.string().uuid().safeParse((request.params as { id?: string }).id);
    const parsed = failureSchema.safeParse(request.body);
    if (!id.success || !parsed.success) return reply.code(400).send({ error: "invalid_build_failure" });
    if (!workerLeaseAuthorized(request, reply, parsed.data.leaseToken)) return;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `UPDATE forgeos_build_jobs SET
          status=CASE WHEN $4::boolean AND attempts < max_attempts THEN 'pending' ELSE 'failed' END,
          error_code=$5,error_message=$6,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
          completed_at=CASE WHEN NOT ($4::boolean AND attempts < max_attempts) THEN now() ELSE NULL END,
          updated_at=now()
         WHERE id=$1 AND status='leased' AND worker_id=$2 AND lease_token=$3 AND lease_expires_at > now()
         RETURNING id,status,configuration_id,attempts,max_attempts`,
        [id.data, parsed.data.workerId, parsed.data.leaseToken, parsed.data.retryable,
          parsed.data.errorCode, parsed.data.message]
      );
      if (!result.rowCount) {
        await client.query("ROLLBACK");
        return reply.code(409).send({ error: "worker_lease_lost" });
      }
      await client.query(
        "INSERT INTO forgeos_build_job_events(build_job_id,attempt,worker_id,event_type,details) VALUES($1,$2,$3,'worker_reported_failure',$4)",
        [result.rows[0]!.id, result.rows[0]!.attempts, parsed.data.workerId, JSON.stringify({ status: result.rows[0]!.status, errorCode: parsed.data.errorCode, retryable: parsed.data.retryable })]
      );
      if (result.rows[0]!.status === "failed") {
        await client.query("UPDATE forgeos_rom_configurations SET status='draft' WHERE id=$1 AND status='queued'", [result.rows[0]!.configuration_id]);
      }
      await client.query("COMMIT");
      const { configuration_id: _configurationId, ...job } = result.rows[0]!;
      return { job };
    } catch (error) {
      await client.query("ROLLBACK");
      request.log.error(error);
      return reply.code(500).send({ error: "build_failure_recording_failed" });
    } finally {
      client.release();
    }
  });
}
