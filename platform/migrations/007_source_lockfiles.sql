ALTER TABLE forgeos_build_jobs
  ADD COLUMN IF NOT EXISTS source_lockfile jsonb,
  ADD COLUMN IF NOT EXISTS source_lockfile_sha256 char(64);

DO $$ BEGIN
  ALTER TABLE forgeos_build_jobs
    ADD CONSTRAINT forgeos_build_job_source_lockfile_consistency
    CHECK (
      (source_lockfile IS NULL AND source_lockfile_sha256 IS NULL)
      OR
      (source_lockfile IS NOT NULL
       AND source_lockfile_sha256 IS NOT NULL
       AND source_lockfile_sha256 ~ '^[a-f0-9]{64}$'
       AND jsonb_typeof(source_lockfile) = 'object')
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
