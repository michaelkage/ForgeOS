CREATE TABLE IF NOT EXISTS forgeos_build_job_events (
  id bigserial PRIMARY KEY,
  build_job_id uuid NOT NULL REFERENCES forgeos_build_jobs(id) ON DELETE CASCADE,
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  worker_id text CHECK (worker_id IS NULL OR worker_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$'),
  event_type text NOT NULL CHECK (event_type IN (
    'queued',
    'claimed',
    'artifact_upload_authorized',
    'artifact_verified',
    'cancelled',
    'worker_reported_failure'
  )),
  details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (octet_length(details::text) <= 8192),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS forgeos_build_job_events_job_id_idx
  ON forgeos_build_job_events(build_job_id, id);

CREATE OR REPLACE FUNCTION forgeos_reject_build_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'build job events are append-only';
END;
$$;

DROP TRIGGER IF EXISTS forgeos_build_job_events_append_only ON forgeos_build_job_events;
CREATE TRIGGER forgeos_build_job_events_append_only
  BEFORE UPDATE OR DELETE ON forgeos_build_job_events
  FOR EACH ROW EXECUTE FUNCTION forgeos_reject_build_event_mutation();
