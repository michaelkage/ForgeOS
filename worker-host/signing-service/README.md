# ForgeOS isolated OTA signing service

This is a separate service intended for a dedicated signing host. It is not part of the Android guest, Firecracker host daemon, or platform API process. The release private key is read only by this service. The guest receives neither the key nor signing credentials.

## Trust boundary

- Bind to a private management interface only; the default development bind is loopback.
- Require TLS 1.3 and a client certificate issued by the dedicated platform-client CA.
- Also require a separate bearer token and pin the exact platform API client-certificate SHA-256. Deliver client key material and the token only to the platform API's signing adapter.
- Firewall the listener so only the platform API can reach it.
- Keep the release certificate and PKCS#8 private key on the signing host. The service verifies they are regular root-owned files and rejects group/world-writable key material.
- Keep the Java runtime, signapk.jar, and release certificate root-owned and non-writable. The service requires and verifies SHA-256 pins for signapk.jar, the release certificate, and the PKCS#8 private key before it starts.
- Use a dedicated service account, a private 0700 work directory, encrypted storage, and the supplied systemd hardening unit.
- The audit ledger is hash-chained JSONL. Set the ledger file's Linux append-only attribute (chattr +a) after first creation and ship a copy to an independently administered append-only log store. Do not allow the signing service account to clear that attribute.

## API

POST /v1/sign accepts an unsigned application/zip body. Required headers:

- Authorization: Bearer <service token>
- X-ForgeOS-Job-ID: <UUID>
- X-ForgeOS-Attempt: <1..20>
- X-ForgeOS-Snapshot-SHA256: <64 lowercase hex>
- X-ForgeOS-Artifact-SHA256: <64 lowercase hex>

The service checks the request's content length and streamed SHA-256, validates the OTA ZIP, reserves the job/attempt in its audit ledger, signs using the configured Android signapk.jar, and runs jarsigner -verify -certs plus ZIP signature-entry checks. The response is the signed ZIP with X-ForgeOS-Signed-SHA256.

A job attempt can be reserved only once. A completed identical request returns the cached signed output after rechecking its digest. A signing attempt left in an incomplete state after a crash is deliberately blocked for operator investigation rather than automatically replayed.

## Deployment

1. Provision a dedicated Linux machine on an isolated management network. It must not be the Firecracker host.
2. Create forgeos-signing user/group and an encrypted filesystem mounted at /var/lib/forgeos-signing, mode 0700, owned by that account.
3. Install a pinned JDK, reviewed signapk.jar, and the release certificate. Verify checksums before deployment.
4. Provision the TLS server key/certificate and platform client CA. Install the release PKCS#8 key as root-owned and readable only by the signing service group (for example mode 0440); never place it in the repository, guest image, host-agent filesystem, or platform database. Compute and set the exact SHA-256 digests for signapk.jar, the release certificate, and the private key in the signing environment file.
5. Install the signing environment file as root-owned mode 0640. Replace all example values and provision a high-entropy bearer token through the secret manager.
6. Build the service from worker-host with CGO_ENABLED=0, install it at /usr/local/sbin/forgeos-signing-service, and install the systemd unit.
7. Restrict firewall ingress to the platform API's exact private address. The sample unit allows 10.0.0.5/32; replace it with the real orchestrator address.
8. Start the service, verify mTLS from the platform API host, and test signing with a non-production test key before installing the production key.

    cd worker-host
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/forgeos-signing-service ./cmd/forgeos-signing-service
    go test -race ./...

## Important limitations

- This is a separate key-bearing signing service, but the current implementation loads a root-protected PKCS#8 key file. It is not HSM-backed and does not claim hardware key isolation. A production signing-key migration to an HSM/KMS-backed signer remains required for stronger key protection.
- The platform API adapter that streams verified uploaded artifacts to this service and stores the returned signed ZIP is not yet wired. Until that integration and post-signature artifact verification are complete, the service is a standalone boundary and build outputs remain unsigned.
- The service does not prove that a caller-supplied job ID/snapshot digest corresponds to a completed platform job. Its mTLS identity and bearer token currently establish trust in the platform API caller. The future adapter must call it only after the platform has independently verified the uploaded artifact against the active job lease.
- Keep ENABLE_ANDROID_BUILDS=false and FORGEOS_SCHEDULER_ENABLED=false until the platform adapter, real signer-host deployment, HSM/KMS migration decision, and privileged Firecracker end-to-end tests are complete.
