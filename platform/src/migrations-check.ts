import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import pg from "pg";

const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error("DATABASE_URL is required for migration verification");
const client = new pg.Client({ connectionString });
try {
  await client.connect();
  const migrations = [
    new URL("../migrations/001_auth_devices_configs.sql", import.meta.url),
    new URL("../migrations/002_device_source_provenance.sql", import.meta.url),
    new URL("../migrations/003_build_queue.sql", import.meta.url)
  ];
  for (const migration of migrations) {
    await client.query(await readFile(migration, "utf8"));
  }
  const columns = await client.query(
    "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='forgeos_device_sources'"
  );
  const names = new Set(columns.rows.map(row => row.column_name));
  for (const required of ["device_id", "source_kind", "rom_base", "repository_url", "branch_name", "verification_status", "verified_commit_sha"]) {
    assert.ok(names.has(required), "Missing migration column: " + required);
  }
  const constraints = await client.query(
    "SELECT conname FROM pg_constraint WHERE conrelid='forgeos_device_sources'::regclass"
  );
  assert.ok(constraints.rows.some(row => row.conname === "forgeos_source_rom_base_check"));
  const indexes = await client.query(
    "SELECT indexname FROM pg_indexes WHERE schemaname='public' AND tablename='forgeos_device_sources'"
  );
  assert.ok(indexes.rows.some(row => row.indexname === "forgeos_device_sources_unscoped_unique_idx"));

  const jobColumns = await client.query(
    "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='forgeos_build_jobs'"
  );
  const jobNames = new Set(jobColumns.rows.map(row => row.column_name));
  for (const required of ["snapshot", "snapshot_sha256", "status", "attempts", "lease_token", "lease_expires_at", "artifact_sha256"]) {
    assert.ok(jobNames.has(required), "Missing build queue column: " + required);
  }
  const jobIndexes = await client.query(
    "SELECT indexname FROM pg_indexes WHERE schemaname='public' AND tablename='forgeos_build_jobs'"
  );
  assert.ok(jobIndexes.rows.some(row => row.indexname === "forgeos_build_jobs_one_active_per_config_idx"));
  const snapshotTrigger = await client.query(
    "SELECT tgname FROM pg_trigger WHERE tgrelid='forgeos_build_jobs'::regclass AND NOT tgisinternal"
  );
  assert.ok(snapshotTrigger.rows.some(row => row.tgname === "forgeos_build_jobs_immutable_snapshot"));
} finally {
  await client.end();
}
