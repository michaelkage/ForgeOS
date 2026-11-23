# ForgeOS build execution security design

Status: mixed implementation and architecture contract. The API now implements S3-compatible SigV4 presigned upload/download URLs, lease-bound upload intents, conditional write-once uploads, server-side HEAD checks, streamed SHA-256 verification, and owner-authorized downloads. This does not mean a storage provider is configured or that build execution is safe to enable. Disposable Android worker isolation, process-tree cancellation, isolated ROM signing, and production observability are not implemented. Keep `ENABLE_ANDROID_BUILDS=false` until every launch gate below is implemented and tested.

## Trust boundaries

The API is the control plane. It authenticates users, validates immutable build snapshots, allocates leases, authorizes artifact access, and records state. It must never execute repository-provided build scripts, mount signing keys, or proxy arbitrary worker traffic.

Build workers are disposable, single-job execution environments. Treat every manifest, device tree, kernel tree, vendor tree, build script, downloaded archive, and generated artifact as untrusted. A worker receives only a job snapshot, a short-lived job-scoped storage capability, and the minimum control-plane credentials needed to heartbeat and report status. The shared worker secret currently used by the queue is a bootstrap mechanism, not a suitable long-term per-worker identity system.

The artifact bucket is private and separate from the API filesystem. Objects are addressed by server-generated keys under a job/user namespace. Clients never choose bucket names, arbitrary object keys, ACLs, or storage endpoints. No public ACL or anonymous bucket policy is permitted.

The signing service is a separate trust domain. Neither the API nor general build workers receive production signing private keys. Signing accepts only a completed, verified unsigned artifact and an explicit signing policy; it returns a signed artifact plus an auditable signing record.

## Required implementation sequence

### 1. Private S3-compatible artifact storage

Use an S3-compatible provider (AWS S3 or MinIO) with:
- bucket-level public access blocks and private bucket policy;
- TLS-only access, server-side encryption, lifecycle expiry, and versioning where supported;
- dedicated credentials scoped to one bucket and the minimum required object operations;
- separate API and worker credentials; no credentials in browser code or build snapshots;
- server-generated object keys, for example `artifacts/<user-uuid>/<job-uuid>/<attempt>/<random-id>.zip`;
- short-lived presigned PUT and GET URLs, constrained to a single object and expected content type;
- no user-controlled bucket, endpoint, key prefix, ACL, or response header.

The API must create an upload intent only for the active lease matching job ID, worker ID, and lease token. The intent binds the expected object key, maximum size (20 GiB), and ZIP content type. The worker uploads directly to private storage; the API does not accept multi-gigabyte request bodies.

### 2. Artifact verification and downloads

Implemented in the platform API: the worker obtains a ten-minute upload intent tied to its live lease, expected SHA-256, and exact byte count. The server generates the object key and SigV4 PUT URL. The required headers include `Content-Length`, `Content-Type: application/zip`, and `If-None-Match: *`. Completion requires the same object key/digest/size; the API checks the lease and intent, performs HEAD validation, streams the object through SHA-256, then records verified metadata. User downloads are owner-scoped and use a five-minute presigned GET URL. Configuration requires all S3 settings together, and production endpoints must use HTTPS. This code still needs integration testing against the selected AWS/MinIO provider and production bucket policy.



A worker's completion report is only a claim, never proof. Before changing a job to `succeeded`, the API must:
1. lock and re-check the live lease;
2. HEAD the exact server-issued object key using server-side storage credentials;
3. reject absent objects, unexpected size, or unexpected content type;
4. stream the object through SHA-256 verification (do not buffer a 20 GiB object in memory);
5. compare the digest and size to the upload intent and completion report;
6. atomically persist verified metadata and mark the job successful.

Downloads require an authenticated user session and an ownership query on both job ID and user ID. Only succeeded jobs with verified artifact metadata may receive a short-lived presigned GET URL. Never return raw bucket credentials or accept an object key from the caller. Log issuance without logging the signed URL.

### 3. Disposable Android build workers

Workers run one job per disposable VM or isolated microVM. A container alone is not a sufficient hostile-code boundary for untrusted Android build scripts. The production worker host must provide:
- non-root execution, no privileged mode, no host PID/network namespaces, no Docker socket, no host mounts, and no Linux capabilities;
- hard CPU, memory, disk, process-count, and wall-clock limits;
- ephemeral encrypted workspace destroyed after each job;
- read-only base image and pinned worker image digest;
- seccomp plus AppArmor/SELinux or an equivalent mandatory access-control profile;
- egress allowlist for required source mirrors and the artifact endpoint; deny metadata services, private networks, and control-plane admin endpoints;
- bounded logs and output size, plus disk exhaustion protection;
- worker registration and short-lived identity, per-job credentials, and lease-bound upload authorization.

Do not run multiple customers' jobs in the same writable workspace or worker VM. Do not reuse a worker after an untrusted build has run.

### 4. Cancellation propagation

Cancellation is a control-plane state transition and a worker process lifecycle event:
- workers poll/heartbeat at a bounded interval and treat lease loss, cancellation, or failed heartbeat as a hard stop;
- the worker supervisor sends SIGTERM to the complete build process group, waits a short grace period, then SIGKILLs the process group;
- child processes must be placed in a dedicated cgroup/process group so shell grandchildren cannot survive cancellation;
- stop source sync, build, upload, and log streaming after cancellation;
- incomplete uploads are aborted and attempt-scoped temporary objects are deleted;
- completion/failure calls after lease loss are rejected; cancellation must remain terminal.

The API must expose cancellation state to the worker protocol rather than relying on lease expiration alone. A lost network connection must fail closed.

### 5. Isolated ROM signing

Signing is a separate service and separate key-management boundary:
- private keys live in KMS/HSM or an offline signing appliance, never in environment variables, worker images, API storage, or build workspaces;
- build workers produce unsigned artifacts and a machine-readable provenance manifest;
- the signer independently verifies job identity, approved source snapshot, artifact digest, target signing profile, and policy;
- signing requests are authenticated, replay-resistant, idempotent, and auditable;
- signer output is re-hashed and stored as a distinct immutable artifact version;
- production signing profiles require explicit operator approval and key rotation/revocation procedures.

Never expose signing keys to arbitrary build scripts, even temporarily.

### 6. Logs, accounting, and monitoring

Persist structured, append-only job events with server timestamps, job/attempt/worker identifiers, event type, and bounded sanitized payload. Keep build stdout/stderr as attempt-scoped log objects with size limits and short-lived owner-authorized access. Redact cookies, bearer tokens, signed URLs, credentials, and secret-like values before persistence.

Record per-attempt CPU time, peak memory, disk peak, elapsed time, bytes downloaded/uploaded, exit code, worker image digest, and termination reason. Enforce quotas using measured resource consumption, not worker-reported estimates alone.

Expose operational metrics for queue depth/age, lease expirations, retries, cancellations, worker capacity, artifact verification failures, build duration, resource usage, and signing failures. Alert on stuck leases, repeated worker crashes, abnormal egress, storage growth, and any signing-policy rejection. Health checks must distinguish API liveness, database readiness, and worker/storage dependencies.

## Launch gates

Do not enable Android builds until all of the following are true:
- isolated disposable worker runtime is deployed and threat-reviewed;
- job-scoped worker identity and lease-bound upload intents replace the shared-secret-only trust model;
- private storage upload, streamed checksum verification, and owner-only download are implemented;
- cancellation reaches and kills the complete process tree;
- signing is isolated behind a reviewed service and managed key boundary;
- structured logs, quotas, resource accounting, alerting, and retention policies are active;
- integration tests cover forged completion metadata, cross-user download attempts, expired leases, cancellation races, oversized uploads, path/key injection, and storage outages.
