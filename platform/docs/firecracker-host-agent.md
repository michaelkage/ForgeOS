# Firecracker host-agent and guest bootstrap boundary

## Status

This change adds the platform-side client for a privileged Firecracker host agent and the guest-side verifier for a signed, single-job bootstrap envelope. It does **not** install Firecracker, implement the privileged host daemon, create Linux TAP/cgroup/jailer resources, build the guest image, or enable Android builds. The adapter intentionally fails closed until a host agent implementing this protocol is deployed and its Ed25519 public key is pinned.

## Host-agent transport

The platform talks to a dedicated HTTPS endpoint using a service credential that is distinct from user sessions and guest bootstrap credentials. The endpoint must not redirect requests. Responses are limited to 64 KiB. The platform pins the host agent's Ed25519 SPKI public key independently of the host agent response.

### Provision

`POST /v1/workers`

Request JSON:
- `requestId`: platform-generated UUID nonce
- `jobId`, `attempt`, `architecture`
- `romBase`
- `imageDigest`: immutable `sha256:<64 lowercase hex>`
- `resources`: CPU, memory, disk, process, and wall-clock limits
- `egressPolicyId`
- `bootstrapCredential`: short-lived one-job credential; never log it

Response JSON:
- `instance`: provider, instanceId, jobId, attempt, architecture, imageDigest, createdAt
- `attestation.payload`: provider, instanceId, jobId, attempt, architecture, imageDigest, requestNonce, isolationProfile, issuedAt, expiresAt
- `attestation.signature`: base64 Ed25519 signature over canonical JSON of payload

The signed isolation profile must exactly match the request and assert Firecracker microVM, dedicated kernel, jailer, non-root VMM, no host mounts, no container socket, no host PID namespace, encrypted ephemeral disk, hard CPU/memory/disk/process limits, wall-clock limit, egress filtering, metadata blocking, and destroy-after-job. A declaration without a valid signature from the pinned host key is rejected.

### Inspect

`GET /v1/workers/{instanceId}`

Returns provider, instanceId, state (`running`, `stopped`, or `unknown`), observedAt, and signature. The signature covers the other four fields as canonical JSON. The platform rejects stale, mismatched, or unsigned state.

### Terminate

`POST /v1/workers/{instanceId}/terminate`

Request JSON: requestId and reason.

Response JSON: provider, instanceId, accepted=true, requestId, signature. The signature covers the other four fields. This is an acknowledgement only; the platform still performs a separate signed inspect and requires state `stopped` before treating teardown as confirmed.

## Host-agent implementation requirements

The privileged host agent is a separate trust boundary and must:
1. Authenticate the platform service credential and authorize only the worker lifecycle API.
2. Validate all identifiers, image digests, resource bounds, architecture, and allowlisted egress policy IDs.
3. Create a fresh Firecracker microVM for exactly one job using a pinned kernel and immutable rootfs image.
4. Run Firecracker under jailer with a dedicated unprivileged UID, isolated mount/PID namespaces, and no host filesystem or container socket mounts.
5. Apply host-enforced cgroup v2 CPU, memory, PID, and I/O limits; enforce disk quotas on encrypted ephemeral storage.
6. Create per-VM TAP networking and enforce default-deny egress at the host firewall. Explicitly block cloud metadata and host/control-plane management networks.
7. Inject the signed guest bootstrap over a dedicated vsock channel; do not expose the bootstrap credential in VM metadata, command lines, environment variables, logs, or HTTP URLs.
8. Enforce a monotonic wall-clock deadline independent of guest cooperation.
9. Destroy the VMM, TAP device, cgroups, namespaces, ephemeral disk, and credentials on success, failure, cancellation, and host-agent restart recovery.
10. Sign provision, state, and termination responses with the pinned Ed25519 key. Keep the private key outside the guest and outside the platform database.

The host agent must not sign a requested profile merely because it was requested: each claim must be derived from successful host-side setup and inspection. A host agent that cannot prove a control must refuse provisioning.

## Guest bootstrap

The guest init process receives one bounded envelope over the authenticated vsock bootstrap channel and calls `verifyGuestBootstrap` before starting any worker activity. The verifier checks the pinned host signature, job/attempt/architecture/image binding, HTTPS API endpoint, credential bounds, nonce shape, and a short validity window. The vsock framing, credential redemption endpoint, guest init integration, and Android build execution remain separate implementation tasks.

## Operational gates

- Do not set `ENABLE_ANDROID_BUILDS=true` with only this adapter installed.
- Deploy and independently review the host agent before registering it as an eligible provider.
- Add host integration tests on the target Linux kernel covering cgroup enforcement, TAP/firewall policy, metadata blocking, disk encryption/quota, kill/restart recovery, and confirmed teardown.
- Add a signed guest image build pipeline and verify the image digest before provisioning.
- Add one-time bootstrap credential redemption and revocation in the control plane.
- Implement a separate signing service backed by KMS/HSM; never expose release signing keys to the guest VM.


## One-time guest credential lifecycle

`POST /api/internal/guest-bootstrap/issue` is authenticated with the platform worker service credential. Its strict body contains `jobId`, `workerId`, and the active `leaseToken`. The platform locks and verifies the unexpired lease, then returns a random 256-bit URL-safe credential with a three-minute expiry. Only its SHA-256 digest is persisted. Re-issuing for the same attempt replaces the previous digest.

`POST /api/internal/guest-bootstrap/redeem` accepts that credential as an HTTPS bearer token. Redemption atomically deletes the digest and returns the immutable job snapshot, snapshot digest, worker identity, attempt, and current lease token. A replay or concurrent second redemption fails. The lease must still be active and match the original worker and attempt.

The credential table has no plaintext credential column. The issue endpoint remains unavailable unless build workers are explicitly enabled. This API does not provision a VM or enable Android builds.

The host agent must issue only after obtaining a valid platform lease and deliver the credential exclusively over the authenticated vsock bootstrap envelope. The guest must verify the signed envelope before redemption and never write credentials to disk or logs. The missing scheduler still must own claim → issue → provision → bootstrap → monitor → terminate → signed stopped-state confirmation.


## Linux host daemon and guest runtime

The repository now contains a standalone Go host daemon and a guest init/runtime. The host daemon implements the provider protocol at HTTPS endpoints POST /v1/workers, GET /v1/workers/{id}, and POST /v1/workers/{id}/terminate. It only signs a provisioning response after host resource setup, Firecracker boot, delivery of the signed vsock envelope, guest signature verification, one-time platform credential redemption, and immutable snapshot digest verification have succeeded.

The Linux runtime requires KVM, cgroup v2 CPU/memory/PID/I/O controllers, Firecracker and its matching jailer, LUKS2, ext4 tools, iproute2, nftables, and ACL utilities. It creates per-VM cgroups, encrypted fixed-size ephemeral storage, a private network namespace, TAP and veth devices, default-deny egress filters, and a bounded workspace disk. Teardown kills the VM cgroup before removing network rules/interfaces, unmounting storage, closing the LUKS mapping, and deleting the cgroup. If processes remain or encrypted storage cannot be unmounted, teardown fails and the signed state endpoint does not report stopped.

The guest agent listens on AF_VSOCK, verifies the host Ed25519 envelope, redeems the one-use credential, verifies the immutable snapshot digest, mounts the encrypted workspace drive, renews the job lease, runs the immutable build-worker executable from the guest image, and uploads/completes the artifact through the platform's existing lease and artifact APIs. The build-worker executable itself must be baked into the approved immutable guest image; the host daemon does not accept a guest-supplied executable path.

The host daemon must be deployed as a dedicated root service on a dedicated Linux host. Configure a delegated cgroup subtree with CPU, memory, PID, and I/O controllers; place the host-agent process outside the child cgroup subtree it manages. Configure a reserved UID/GID pool, root-owned kernel and worker image files, an Ed25519 host-attestation key, and the pinned matching Firecracker/jailer release. Use TLS 1.3 and a dedicated host-agent bearer token. Keep the host signing key distinct from all ROM release-signing keys.

Build checks are automated with Go formatting, race-enabled tests, vet, and binary compilation. CI does not prove that KVM, cgroup, nftables, LUKS, jailer, vsock, or guest teardown work on the production kernel. A dedicated privileged-host integration run and independent security review remain mandatory before production enablement.
