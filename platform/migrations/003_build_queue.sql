DO $$ BEGIN
  CREATE TYPE forgeos_build_job_status AS ENUM ('pending','leased','succeeded','failed','cancelled');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS forgeos_build_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES forgeos_users(id) ON DELETE CASCADE,
  configuration_id uuid NOT NULL REFERENCES forgeos_rom_configurations(id) ON DELETE RESTRICT,
  status forgeos_build_job_status NOT NULL DEFAULT 'pending',
  snapshot jsonb NOT NULL,
  snapshot_sha256 char(64) NOT NULL CHECK (snapshot_sha256 ~ '^[a-f0-9]{64}$'),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
  worker_id text,
  lease_token uuid,
  lease_expires_at timestamptz,
  error_code text,
  error_message text,
  artifact_object_key text,
  artifact_sha256 char(64),
  artifact_size_bytes bigint,
  artifact_content_type text,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT forgeos_build_job_lease_consistency CHECK (
    (status = 'leased' AND worker_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR (status <> 'leased' AND worker_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
  ),
  CONSTRAINT forgeos_build_job_artifact_consistency CHECK (
    status <> 'succeeded' OR
    (artifact_object_key IS NOT NULL AND artifact_sha256 ~ '^[a-f0-9]{64}$'
     AND artifact_size_bytes > 0 AND artifact_content_type = 'application/zip')
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS forgeos_build_jobs_one_active_per_config_idx
  ON forgeos_build_jobs(configuration_id) WHERE status IN ('pending','leased');
CREATE INDEX IF NOT EXISTS forgeos_build_jobs_claim_idx
  ON forgeos_build_jobs(status,created_at) WHERE status='pending';
CREATE INDEX IF NOT EXISTS forgeos_build_jobs_user_created_idx
  ON forgeos_build_jobs(user_id,created_at DESC);
CREATE INDEX IF NOT EXISTS forgeos_build_jobs_expired_lease_idx
  ON forgeos_build_jobs(lease_expires_at) WHERE status='leased';

DROP TRIGGER IF EXISTS forgeos_build_jobs_touch ON forgeos_build_jobs;
CREATE TRIGGER forgeos_build_jobs_touch BEFORE UPDATE ON forgeos_build_jobs
FOR EACH ROW EXECUTE FUNCTION forgeos_touch_updated_at();
