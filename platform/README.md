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
- Build queue endpoint intentionally returns 503 until isolated Android workers and artifact/signing infrastructure exist.

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
    npm install
    npm run typecheck
    npm test
    npm run dev

The API listens on http://127.0.0.1:4100 by default. Set MANIFEST_ROOT to the absolute repository root if the service is not launched from this directory. /healthz is a liveness check and /readyz checks the database.

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
- POST /api/configurations/:id/queue — deliberately disabled (503)

Mutating authenticated requests require the CSRF token returned by login/register or /api/auth/me in the x-csrf-token header. Send the session cookie with credentials from the frontend.

## Production gaps

Before public deployment, add email verification and password reset, MFA/passkeys, session revocation UI, audit logs, stricter integration tests, and observability. Add reviewed device profile import/sync and signed provenance before enabling public device support. Root options are recorded for configuration continuity but are not injected. Build submission remains blocked until an isolated worker, quotas, artifact storage, signing, and a threat-reviewed build pipeline are deployed.

Never put signing keys, Git credentials, vendor blobs, or build secrets in this service or in the browser.
