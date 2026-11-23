DO $$
BEGIN
  CREATE TYPE forgeos_device_source_kind AS ENUM ('device', 'kernel', 'vendor');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE forgeos_source_verification_status AS ENUM ('pending', 'verified', 'failed');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS forgeos_device_sources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES forgeos_devices(id) ON DELETE CASCADE,
  source_kind forgeos_device_source_kind NOT NULL,
  rom_base forgeos_rom_base,
  repository_url text NOT NULL,
  branch_name text NOT NULL,
  source_path text NOT NULL DEFAULT '',
  verification_status forgeos_source_verification_status NOT NULL DEFAULT 'pending',
  verified_commit_sha text,
  verified_files jsonb NOT NULL DEFAULT '[]'::jsonb,
  verification_error text,
  last_checked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT forgeos_source_repository_url_check CHECK (
    repository_url ~ '^https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+([.]git)?$'
  ),
  CONSTRAINT forgeos_source_branch_check CHECK (
    branch_name ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$'
    AND branch_name !~ '(^/|/$|//|[.][.]|@[{]|[.]lock$)'
  ),
  CONSTRAINT forgeos_source_rom_base_check CHECK (
    source_kind <> 'device' OR rom_base IS NOT NULL
  ),
  CONSTRAINT forgeos_source_path_check CHECK (
    source_path = '' OR (
      source_path !~ '(^/|(^|/)\.\.(/|$)|[[:cntrl:]])'
      AND length(source_path) <= 240
    )
  ),
  CONSTRAINT forgeos_source_files_array CHECK (jsonb_typeof(verified_files) = 'array'),
  UNIQUE(device_id, source_kind, rom_base, repository_url, branch_name, source_path)
);

CREATE INDEX IF NOT EXISTS forgeos_device_sources_device_idx
  ON forgeos_device_sources(device_id, source_kind);

CREATE UNIQUE INDEX IF NOT EXISTS forgeos_device_sources_unscoped_unique_idx
  ON forgeos_device_sources(device_id, source_kind, repository_url, branch_name, source_path)
  WHERE rom_base IS NULL;

DROP TRIGGER IF EXISTS forgeos_device_sources_touch ON forgeos_device_sources;
CREATE TRIGGER forgeos_device_sources_touch
  BEFORE UPDATE ON forgeos_device_sources
  FOR EACH ROW EXECUTE FUNCTION forgeos_touch_updated_at();
