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
- Provider-neutral disposable worker contract with fail-closed capability checks, immutable worker image digest pinning, bounded resource requests, job-attempt binding, and instance identity validation. This is an adapter contract and validation layer, not a cloud VM implementation.

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
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/004_artifact_storage.sql
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/005_build_job_events.sql
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
- GET /api/build-jobs/:id/events — read up to 100 append-only lifecycle events for an owned job; use the `after` cursor for pagination
- POST /api/build-jobs/:id/cancel — cancel a pending or leased job
- POST /api/build-jobs/:id/download — owner-only short-lived download URL for a verified artifact
- POST /api/internal/build-jobs/claim — worker-only atomic lease claim
- POST /api/internal/build-jobs/:id/heartbeat — worker-only lease renewal
- POST /api/internal/build-jobs/:id/artifact-upload — worker-only lease-bound upload intent and short-lived presigned PUT URL
- POST /api/internal/build-jobs/:id/complete — worker-only completion after server-side artifact verification
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

Before public deployment, add email verification and password reset, MFA/passkeys, session revocation UI, audit logs, periodic upstream source revalidation, signed provenance, and observability. The current GitHub resolver verifies public repository structure and records a commit SHA; it does not establish buildability, maintainer authority, device safety, or licensing rights. Root options are recorded for configuration continuity but are not injected. Keep ENABLE_ANDROID_BUILDS=false until isolated workers, quotas, private artifact storage, signing, and a threat-reviewed build pipeline are deployed; the API's feature flag is an operator gate, not proof that those controls exist.

Never put signing keys, Git credentials, vendor blobs, or build secrets in this service or in the browser.


### Build queue and worker protocol

Apply migrations `003_build_queue.sql`, `004_artifact_storage.sql`, and `005_build_job_events.sql`. Build submission is disabled unless both `ENABLE_ANDROID_BUILDS=true` and a `BUILD_WORKER_SHARED_SECRET` of at least 32 characters are configured. The server refuses startup if builds are enabled without the secret.

A user can enqueue only a configuration whose latest validation report is valid and whose device and ROM base remain enabled. The queue captures the configuration, exact manifest XML bytes and SHA-256, verified device-tree repository/branch/commit, and all additional verified kernel/vendor source inputs applicable to the selected ROM base into a canonical JSON snapshot and stores its SHA-256 fingerprint. Canonical JSON recursively sorts object keys, preserves array order, and serializes only JSON values. PostgreSQL prevents updates to job identity, ownership, configuration association, snapshot, fingerprint, and creation timestamp. Workers should independently recompute the fingerprint before using the snapshot. A partial unique index prevents more than one pending or leased job per configuration. The API limits each account to two active jobs across distinct configurations. Worker claims must declare supported CPU architectures and ROM bases, so incompatible jobs are not leased.

Only the claim/bootstrap endpoint requires `Authorization: Bearer <BUILD_WORKER_SHARED_SECRET>`. A successful claim returns a cryptographically random per-job lease token; use that token as `Authorization: Bearer <leaseToken>` on heartbeat, artifact-upload, completion, and failure calls. The API compares the bearer token to the request lease token in constant time, then checks the live database lease, worker ID, job ID, and expiry. A token cannot authorize another job and is revoked immediately when the lease expires, is cancelled, or is reassigned. Claims use PostgreSQL row locks with `SKIP LOCKED`; each claim returns a unique lease token and expiry. Workers must heartbeat before lease expiry. A stale lease is reclaimed on the next claim, up to three attempts. A worker must include its worker ID and lease token on heartbeat, completion, and failure calls. Claims are capability-matched by architecture and ROM base. Before leasing, the control plane fails pending or leased jobs if the device has been disabled, its ROM base disabled, or its verified device-tree commit no longer matches the queued snapshot; a running worker then loses its lease on its next heartbeat. Before running any source-provided build scripts, the worker must recompute and compare the snapshot SHA-256, use the manifest XML embedded in the snapshot and verify its SHA-256, check out each source at its exact commit SHA (not a mutable branch name), and enforce the snapshot's ROM/manifest compatibility. Lost or expired leases are rejected with HTTP 409.

Claim request:

```json
{ "workerId": "worker-eu-01", "leaseSeconds": 180, "architectures": ["arm64"], "romBases": ["lineage", "crdroid"] }
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

Configure all five S3 settings together: `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, and `S3_SECRET_ACCESS_KEY`. Production requires an HTTPS endpoint. Use a private bucket with public access blocked, TLS-only policy, server-side encryption, lifecycle retention, and credentials scoped to this bucket. The API uses path-style S3-compatible addressing and AWS Signature Version 4. Android build enablement refuses startup unless private storage is configured.

Before uploading, the worker computes the ZIP's SHA-256 and byte size, then requests a lease-bound upload intent:

```json
{
  "workerId": "worker-eu-01",
  "leaseToken": "00000000-0000-4000-8000-000000000001",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "sizeBytes": 123456789
}
```

The API returns a server-generated object key, a short-lived presigned PUT URL, and the exact `content-type`, `content-length`, and `if-none-match: *` headers. The conditional write prevents a replayed upload URL from overwriting an already-created artifact object. The worker uploads directly to storage and reports only the digest, byte size, and content type to completion. The server retrieves the object key from the upload intent; the worker cannot select or substitute a key:

```json
{
  "workerId": "worker-eu-01",
  "leaseToken": "00000000-0000-4000-8000-000000000001",
  "artifact": {
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "sizeBytes": 123456789,
    "contentType": "application/zip"
  }
}
```

The API does not proxy large file uploads. Job lifecycle transitions are also recorded in an append-only PostgreSQL event ledger; event payloads are bounded and omit credentials, bearer tokens, and signed URLs. On completion it checks the live worker lease and unexpired upload intent, performs a storage HEAD check, then streams the object back through SHA-256 verification before it can mark the job successful. It stores the verified timestamp and metadata transactionally. Owner-authorized downloads require an authenticated session and CSRF token and return a five-minute presigned GET URL. The API never accepts a caller-supplied storage key for downloads.

This storage integration does not provide disposable worker isolation, process-tree cancellation, ROM signing, or full resource monitoring. Keep `ENABLE_ANDROID_BUILDS=false` until every launch gate in [BUILD_INFRASTRUCTURE.md](./BUILD_INFRASTRUCTURE.md) is implemented and threat-reviewed. A presigned upload intent is scoped to one job lease and one server-generated object key; workers must never receive the API's S3 credentials.

## Build infrastructure security contract

The required production architecture, trust boundaries, storage verification rules, worker isolation controls, cancellation semantics, signing boundary, observability requirements, and launch gates are documented in [BUILD_INFRASTRUCTURE.md](./BUILD_INFRASTRUCTURE.md). This is an implementation contract, not a claim that these services are deployed. Keep Android build submission disabled until every launch gate is satisfied.
