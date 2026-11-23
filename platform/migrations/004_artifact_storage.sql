CREATE TABLE IF NOT EXISTS forgeos_artifact_upload_intents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  build_job_id uuid NOT NULL REFERENCES forgeos_build_jobs(id) ON DELETE CASCADE,
  worker_id text NOT NULL CHECK (worker_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$'),
  lease_token uuid NOT NULL,
  object_key text NOT NULL UNIQUE CHECK (
    length(object_key) BETWEEN 3 AND 512
    AND object_key ~ '^artifacts/[0-9a-f-]{36}/[0-9a-f-]{36}/[1-9][0-9]*/[A-Za-z0-9-]{16,64}[.]zip$'
  ),
  expected_sha256 char(64) NOT NULL CHECK (expected_sha256 ~ '^[a-f0-9]{64}$'),
  expected_size_bytes bigint NOT NULL CHECK (expected_size_bytes BETWEEN 1 AND 21474836480),
  expires_at timestamptz NOT NULL,
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT forgeos_upload_intent_lease_unique UNIQUE(build_job_id, lease_token)
);

CREATE INDEX IF NOT EXISTS forgeos_artifact_upload_intents_expiry_idx
  ON forgeos_artifact_upload_intents(expires_at) WHERE verified_at IS NULL;

ALTER TABLE forgeos_build_jobs
  ADD COLUMN IF NOT EXISTS artifact_verified_at timestamptz;

UPDATE forgeos_build_jobs
SET status='failed',
    error_code='legacy_artifact_unverified',
    error_message='Artifact metadata predates server-side object verification',
    completed_at=COALESCE(completed_at, now()),
    worker_id=NULL,lease_token=NULL,lease_expires_at=NULL
WHERE status='succeeded' AND artifact_verified_at IS NULL;

DO $$ BEGIN
  ALTER TABLE forgeos_build_jobs
    ADD CONSTRAINT forgeos_build_job_verified_artifact_check
    CHECK (status <> 'succeeded' OR artifact_verified_at IS NOT NULL);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
