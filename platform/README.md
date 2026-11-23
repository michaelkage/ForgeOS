# ForgeOS platform API

This service adds account authentication, administrator-managed device profiles, and saved ROM configurations to the existing Android Repo manifest repository. It serves a browser-based ROM configurator at the service root. It does not compile Android source.

## Implemented

- Email/password registration and login using Argon2id.
- Opaque random session cookies; only SHA-256 token hashes are stored in PostgreSQL.
- HttpOnly, SameSite=Lax cookies, CSRF checks on mutations, origin checking, security headers, and per-IP rate limits.
- User/admin roles. Public users can view enabled devices; only admins can create, update, disable, and activate device profiles.
- GitHub-backed source provenance for device trees, kernel trees, and vendor source repositories. Device activation is blocked until a device-tree branch is verified.
- Per-device ROM base compatibility records tied to manifest paths and branches.
- User-owned ROM configurations with draft, save, update, and validate operations.
- XML manifest syntax checks, root element checks, safe project path checks, and duplicate project path checks.
- Durable build-job queue with immutable configuration/source snapshots, SHA-256 fingerprints, owner-scoped status/cancellation, authenticated worker claims, expiring leases, heartbeats, retry limits, and artifact metadata validation. Android execution remains disabled by default.

## Repository-specific scope

The repository currently contains default.xml (LineageOS 24.0 default manifest) and snippets/crdroid.xml (crDroid 17.0 additions). The schema therefore enables only lineage and crdroid, and restricts manifest paths to those two files. Evolution X and GrapheneOS are in the product blueprint but are not represented by verified manifests in this repository yet.

No device records are seeded. A maintainer registers a device-tree GitHub repository and a separate branch/path for every enabled ROM base. The resolver verifies each repository and branch, captures the commit SHA, and checks for AndroidProducts.mk, BoardConfig.mk, and a device makefile before activation. A device cannot be enabled unless every enabled ROM base has a verified device-tree source. Kernel and vendor sources can also be registered and verified, but device activation currently requires the device-tree source only. Verification proves that the selected public repository/branch has the expected structure; it does not prove that the source builds or that proprietary blobs are legally redistributable. Maintainers remain responsible for compatibility review.

## Requirements and setup

Requirements: Node.js 22+, PostgreSQL 15+, npm.

From this directory:

    cp .env.example .env
    # Set DATABASE_URL and WEB_ORIGIN in .env. Set GITHUB_TOKEN to a fine-grained read-only GitHub token to avoid low unauthenticated API limits (optional for public repositories).
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_auth_devices_configs.sql
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/002_device_source_provenance.sql
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/003_build_queue.sql
    npm install
    npm run typecheck
    npm test
    npm run dev

The API listens on http://127.0.0.1:4100 by default. Set HOST=0.0.0.0 in a container, and set TRUST_PROXY only to the actual reverse-proxy IP addresses or CIDRs. Do not trust arbitrary forwarded headers. MANIFEST_ROOT defaults to the repository root relative to the application module; override it with an absolute path when the manifest checkout is elsewhere. /healthz is a liveness check and /readyz checks the database.

## First administrator

Registration always creates a regular user. After registering the maintainer account, promote it through a trusted database administrator connection:

    UPDATE forgeos_users SET role='admin' WHERE email='maintainer@example.com';

Do not expose database credentials to the browser or grant users direct SQL access.

## API

- POST /api/auth/register — email and password (minimum 12 characters)
- POST /api/auth/login — email and password
- GET /api/auth/me — current user and CSRF token
- POST /api/auth/logout — requires x-csrf-token
- GET /api/devices — enabled device catalog
- GET /api/admin/devices — admin-only full device catalog, including disabled entries
- POST /api/admin/devices — admin only; creates a disabled device profile and supported ROM base records
- GET /api/admin/devices/:id/sources — admin-only source provenance inventory
- POST /api/admin/devices/:id/sources — register a GitHub device/kernel/vendor source
- POST /api/admin/devices/:id/sources/:sourceId/verify — verify branch and source contents against GitHub
- POST /api/admin/devices/:id/activate — enable a device only after a device-tree source is verified
- PUT /api/admin/devices/:id — admin only; replaces device metadata and supported bases
- DELETE /api/admin/devices/:id — admin only; disables device
- GET /api/configurations — authenticated user's saved configurations
- POST /api/configurations — create a draft
- GET /api/configurations/:id — read an owned configuration
- PUT /api/configurations/:id — update an owned configuration
- POST /api/configurations/:id/validate — validate manifest and device/base mapping
- POST /api/configurations/:id/queue — enqueue a validated configuration when build submission is enabled
- GET /api/build-jobs — list the authenticated user's build jobs
- GET /api/build-jobs/:id — read one owned job
- POST /api/build-jobs/:id/cancel — cancel a pending or leased job
- POST /api/internal/build-jobs/claim — worker-only atomic lease claim
- POST /api/internal/build-jobs/:id/heartbeat — worker-only lease renewal
- POST /api/internal/build-jobs/:id/complete — worker-only completion and artifact metadata registration
- POST /api/internal/build-jobs/:id/fail — worker-only failure reporting and retry scheduling


### Device source registration

Create the device profile disabled, then register and verify one device-tree source for each ROM base that will be enabled:

```json
{
  "sourceKind": "device",
  "romBase": "lineage",
  "repositoryUrl": "https://github.com/LineageOS/android_device_vendor_codename",
  "branchName": "lineage-24.0",
  "sourcePath": ""
}
```

Use `romBase: "crdroid"` and the matching device-tree branch for a crDroid profile. `sourcePath` is a repository-relative directory; an empty string checks the repository root. The API accepts `kernel` and `vendor` source kinds as additional provenance records; their `romBase` is optional. A device is visible in the public catalog only after every enabled ROM base has a verified device-tree source and an administrator activates it.

### ROM configuration payload

```json
{
  "name": "Daily driver",
  "deviceId": "00000000-0000-4000-8000-000000000001",
  "romBase": "lineage",
  "rootMethod": "none",
  "manifestRevision": "lineage-24.0",
  "options": {
    "includeGapps": false,
    "includeMicroG": false,
    "debloatPackages": ["com.example.unwantedapp"],
    "featureFlags": {}
  }
}
```

Google apps and microG are mutually exclusive. Root, app package, and feature selections are persisted as configuration metadata only until the corresponding build-time integrations are implemented.

Mutating authenticated requests require the CSRF token returned by login/register or /api/auth/me in the x-csrf-token header. Send the session cookie with credentials from the frontend.

## Production gaps

Before public deployment, add email verification and password reset, MFA/passkeys, session revocation UI, audit logs, periodic upstream source revalidation, signed provenance, and observability. The current GitHub resolver verifies public repository structure and records a commit SHA; it does not establish buildability, maintainer authority, device safety, or licensing rights. Root options are recorded for configuration continuity but are not injected. Build submission remains blocked until an isolated worker, quotas, artifact storage, signing, and a threat-reviewed build pipeline are deployed.

Never put signing keys, Git credentials, vendor blobs, or build secrets in this service or in the browser.


### Build queue and worker protocol

Apply migration `003_build_queue.sql`. Build submission is disabled unless both `ENABLE_ANDROID_BUILDS=true` and a `BUILD_WORKER_SHARED_SECRET` of at least 32 characters are configured. The server refuses startup if builds are enabled without the secret.

A user can enqueue only a configuration whose latest validation report is valid and whose device and ROM base remain enabled. The queue captures the configuration, manifest mapping, and verified device-tree repository/branch/commit into a canonical JSON snapshot and stores its SHA-256 fingerprint. A partial unique index prevents more than one pending or leased job per configuration.

Worker endpoints require `Authorization: Bearer <BUILD_WORKER_SHARED_SECRET>`. Claims use PostgreSQL row locks with `SKIP LOCKED`; each claim returns a unique lease token and expiry. Workers must heartbeat before lease expiry. A stale lease is reclaimed on the next claim, up to three attempts. A worker must include its worker ID and lease token on heartbeat, completion, and failure calls. Lost or expired leases are rejected with HTTP 409.

Claim request:

```json
{ "workerId": "worker-eu-01", "leaseSeconds": 180 }
```

Heartbeat request:

```json
{ "workerId": "worker-eu-01", "leaseToken": "00000000-0000-4000-8000-000000000001", "leaseSeconds": 180 }
```

Failure request:

```json
{
  "workerId": "worker-eu-01",
  "leaseToken": "00000000-0000-4000-8000-000000000001",
  "errorCode": "source_sync_failed",
  "retryable": true,
  "message": "Repository sync failed with exit code 128"
}
```

Completion is accepted only after the worker has uploaded a ZIP artifact to private object storage. The worker reports its storage key, SHA-256, byte size, and content type:

```json
{
  "workerId": "worker-eu-01",
  "leaseToken": "00000000-0000-4000-8000-000000000001",
  "artifact": {
    "objectKey": "builds/2026/01/job-id/rom.zip",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "sizeBytes": 123456789,
    "contentType": "application/zip"
  }
}
```

The API stores artifact metadata only. It does not accept file uploads, issue signed download URLs, verify the object exists, or sign ROM images. Those operations belong in the isolated worker and private artifact-storage service.
