CREATE TABLE IF NOT EXISTS forgeos_guest_bootstrap_credentials (
  build_job_id uuid NOT NULL REFERENCES forgeos_build_jobs(id) ON DELETE CASCADE,
  attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 20),
  worker_id text NOT NULL CHECK (worker_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$'),
  credential_sha256 char(64) NOT NULL UNIQUE CHECK (credential_sha256 ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  redeemed_at timestamptz,
  PRIMARY KEY (build_job_id, attempt),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '3 minutes')
);

CREATE INDEX IF NOT EXISTS forgeos_guest_bootstrap_credentials_expiry_idx
  ON forgeos_guest_bootstrap_credentials(expires_at);

ALTER TABLE forgeos_guest_bootstrap_credentials
  ADD COLUMN IF NOT EXISTS redeemed_at timestamptz;
