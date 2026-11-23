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
  max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
  attempts integer NOT NULL DEFAULT 0,
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
  CONSTRAINT forgeos_build_job_attempts_check CHECK (attempts BETWEEN 0 AND max_attempts),
  CONSTRAINT forgeos_build_job_lease_consistency CHECK (
    (status = 'leased' AND worker_id IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR (status <> 'leased' AND worker_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
  ),
  CONSTRAINT forgeos_build_job_terminal_timestamp CHECK (
    (status IN ('succeeded','failed','cancelled') AND completed_at IS NOT NULL)
    OR (status IN ('pending','leased') AND completed_at IS NULL)
  ),
  CONSTRAINT forgeos_build_job_artifact_consistency CHECK (
    status <> 'succeeded' OR
    (artifact_object_key IS NOT NULL
     AND length(artifact_object_key) BETWEEN 3 AND 512
     AND artifact_object_key ~ '^[A-Za-z0-9][A-Za-z0-9/_.-]*$'
     AND position('//' IN artifact_object_key) = 0
     AND artifact_sha256 IS NOT NULL
     AND artifact_sha256 ~ '^[a-f0-9]{64}$'
     AND artifact_size_bytes IS NOT NULL
     AND artifact_size_bytes BETWEEN 1 AND 21474836480
     AND artifact_content_type IS NOT NULL
     AND artifact_content_type = 'application/zip')
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

CREATE OR REPLACE FUNCTION forgeos_build_job_protect_snapshot()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.user_id IS DISTINCT FROM OLD.user_id
     OR NEW.configuration_id IS DISTINCT FROM OLD.configuration_id
     OR NEW.snapshot IS DISTINCT FROM OLD.snapshot
     OR NEW.snapshot_sha256 IS DISTINCT FROM OLD.snapshot_sha256
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'Build job identity and input snapshot are immutable'
      USING ERRCODE = '23000';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS forgeos_build_jobs_immutable_snapshot ON forgeos_build_jobs;
CREATE TRIGGER forgeos_build_jobs_immutable_snapshot
BEFORE UPDATE ON forgeos_build_jobs
FOR EACH ROW EXECUTE FUNCTION forgeos_build_job_protect_snapshot();
