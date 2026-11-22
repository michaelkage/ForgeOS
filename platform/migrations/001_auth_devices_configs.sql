CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$ BEGIN
  CREATE TYPE forgeos_user_role AS ENUM ('user', 'admin');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE forgeos_rom_base AS ENUM ('lineage', 'crdroid');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE forgeos_root_method AS ENUM ('none', 'magisk', 'kernelsu', 'apatch');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE forgeos_config_status AS ENUM ('draft', 'validated', 'queued');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS forgeos_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  role forgeos_user_role NOT NULL DEFAULT 'user',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS forgeos_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES forgeos_users(id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,
  csrf_token text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS forgeos_sessions_user_idx ON forgeos_sessions(user_id);
CREATE INDEX IF NOT EXISTS forgeos_sessions_expiry_idx ON forgeos_sessions(expires_at);

CREATE TABLE IF NOT EXISTS forgeos_devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  codename text NOT NULL UNIQUE,
  manufacturer text NOT NULL,
  model text NOT NULL,
  chipset text,
  architecture text NOT NULL DEFAULT 'arm64',
  enabled boolean NOT NULL DEFAULT false,
  notes text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT forgeos_device_codename_check CHECK (codename ~ '^[a-z0-9][a-z0-9_-]{1,63}$')
);

CREATE TABLE IF NOT EXISTS forgeos_device_rom_bases (
  device_id uuid NOT NULL REFERENCES forgeos_devices(id) ON DELETE CASCADE,
  rom_base forgeos_rom_base NOT NULL,
  manifest_path text NOT NULL,
  branch_name text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  PRIMARY KEY (device_id, rom_base),
  CONSTRAINT forgeos_manifest_path_check CHECK (
    manifest_path IN ('default.xml', 'snippets/crdroid.xml')
  ),
  CONSTRAINT forgeos_branch_check CHECK (branch_name ~ '^[A-Za-z0-9._/-]{1,100}$')
);

CREATE TABLE IF NOT EXISTS forgeos_rom_configurations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES forgeos_users(id) ON DELETE CASCADE,
  device_id uuid NOT NULL REFERENCES forgeos_devices(id) ON DELETE RESTRICT,
  name text NOT NULL,
  rom_base forgeos_rom_base NOT NULL,
  root_method forgeos_root_method NOT NULL DEFAULT 'none',
  manifest_revision text,
  options jsonb NOT NULL DEFAULT '{}'::jsonb,
  status forgeos_config_status NOT NULL DEFAULT 'draft',
  validation_report jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT forgeos_config_name_check CHECK (length(trim(name)) BETWEEN 1 AND 80),
  CONSTRAINT forgeos_config_options_object CHECK (jsonb_typeof(options) = 'object')
);
CREATE INDEX IF NOT EXISTS forgeos_configs_user_updated_idx
  ON forgeos_rom_configurations(user_id, updated_at DESC);

CREATE OR REPLACE FUNCTION forgeos_touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS forgeos_users_touch ON forgeos_users;
CREATE TRIGGER forgeos_users_touch BEFORE UPDATE ON forgeos_users
FOR EACH ROW EXECUTE FUNCTION forgeos_touch_updated_at();
DROP TRIGGER IF EXISTS forgeos_devices_touch ON forgeos_devices;
CREATE TRIGGER forgeos_devices_touch BEFORE UPDATE ON forgeos_devices
FOR EACH ROW EXECUTE FUNCTION forgeos_touch_updated_at();
DROP TRIGGER IF EXISTS forgeos_configs_touch ON forgeos_rom_configurations;
CREATE TRIGGER forgeos_configs_touch BEFORE UPDATE ON forgeos_rom_configurations
FOR EACH ROW EXECUTE FUNCTION forgeos_touch_updated_at();

-- Seed only the ROM bases that exist in this repository today. Device rows are
-- deliberately not fabricated: administrators must verify each device tree.
