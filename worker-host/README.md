# ForgeOS worker host and guest runtime

This directory contains two independently built Linux Go binaries:

- forgeos-host-agent: privileged host control plane for Firecracker lifecycle operations.
- forgeos-guest-agent: guest init runtime that verifies signed vsock bootstrap, redeems one-use credentials, applies guest process limits, runs the trusted build worker without root, and uploads the artifact.

## Host prerequisites

Use a dedicated Linux host with KVM, cgroup v2, Firecracker and its matching jailer, cryptsetup with LUKS2, ext4 tools, iproute2, nftables, ACL tools, and a kernel with AF_VSOCK support.

The host agent runs as root because it provisions cgroups, network namespaces, TAP/veth devices, encrypted block storage, and Firecracker jailer processes. It must be a dedicated service, not part of the Node API process. Disable host swap, kernel same-page merging (KSM), and simultaneous multithreading (SMT) before admitting untrusted tenants. Keep the host kernel, microcode, and Firecracker release patched. The runtime refuses to launch when swap, KSM, or SMT are active.

Configure a delegated cgroup v2 subtree for VM children. The host-agent process itself must live outside the cgroup parent configured in the JSON file; that parent must be empty of processes and have cpu, memory, pids, and io controllers available. The service manager must delegate those controllers.

Reserve a numeric UID/GID range for per-VM VMM identities. The range must not overlap real host users or groups. The daemon verifies identities before use and assigns a distinct UID/GID to each live instance.

## Host configuration

HOST_AGENT_CONFIG must point to a root-owned, non-symlink, mode-0600 JSON file. It defines state and jailer directories, the delegated cgroup parent, absolute paths to the jailer and Firecracker binaries, kernel images by architecture, root filesystem images by SHA-256 digest, egress policies, DNS resolvers, a reserved UID/GID pool, disk I/O ceiling, vsock port, and the platform HTTPS origin.

Example shape (replace all paths, digests, addresses, and policy identifiers with reviewed production values):

    {
      "workerId": "forgeos-host-01",
      "stateDir": "/var/lib/forgeos-host-agent",
      "chrootBase": "/srv/forgeos-jailer",
      "cgroupParent": "forgeos-host-agent.slice/instances",
      "jailerPath": "/usr/local/bin/jailer",
      "firecrackerPath": "/usr/local/bin/firecracker",
      "kernelPaths": {
        "x86_64": "/opt/forgeos/images/vmlinux-x86_64",
        "arm64": "/opt/forgeos/images/vmlinux-arm64"
      },
      "imagePaths": {
        "sha256:REPLACE_WITH_64_HEX_DIGEST": "/opt/forgeos/images/worker-rootfs.ext4"
      },
      "egressPolicies": {
        "android-source-egress": ["140.82.112.0/20", "185.199.108.0/22"]
      },
      "dnsResolvers": ["1.1.1.1", "8.8.8.8"],
      "vmmUidBase": 20000,
      "vmmGidBase": 20000,
      "ioBytesPerSecond": 104857600,
      "vsockPort": 4050,
      "bootstrapApiBaseUrl": "https://forgeos.example"
    }

The worker image digest is verified against the actual rootfs bytes before launch. Kernel and rootfs files, Firecracker, and jailer must be root-owned and not group/world writable. Use a pinned matching Firecracker/jailer release.

An optional scheduler object in the host JSON config contains platformApiBaseUrl, workerId, architectures, romBases, leaseSeconds, pollIntervalSeconds, maxConcurrent, resources, imageDigests (keyed by architecture), and egressPolicyId. Set FORGEOS_SCHEDULER_ENABLED=true and PLATFORM_WORKER_TOKEN only after the platform is intentionally configured to enable workers. The worker ID in the scheduler config must match the top-level workerId. The scheduler claims durable jobs, issues one-time credentials, provisions VMs, monitors platform status and lease expiry, and independently confirms teardown after terminal job state.

HOST_AGENT_TOKEN is a dedicated random service bearer credential. HOST_AGENT_SIGNING_KEY points to a root-owned mode-0600 Ed25519 PKCS#8 PEM key. HOST_AGENT_TLS_CERT and HOST_AGENT_TLS_KEY point to root-owned TLS files. The host-attestation key must be separate from all ROM release-signing keys. HOST_AGENT_LISTEN defaults to :9443.

## Guest image requirements

Bake the forgeos-guest-agent binary, the pinned host-agent Ed25519 public key, and a root-owned immutable forgeos-build-worker executable into the approved rootfs image. Configure FORGEOS_HOST_PUBLIC_KEY, FORGEOS_BUILD_WORKER, FORGEOS_ARTIFACT_PATH (inside /workspace/forgeos), and optionally FORGEOS_VSOCK_PORT in the guest image. The worker executable must be root-owned and not writable by group or others.

The guest kernel must expose cgroup v2 and its pids controller. The guest agent moves itself into a control cgroup, enables the pids controller, creates a bounded worker cgroup, and starts the build worker through its own privileged launcher. The worker runs as numeric UID/GID 10000 and does not receive the lease token or platform API credentials.

The rootfs image is the Firecracker root drive. A second ext4 workspace image is created inside the host's LUKS2 volume and attached as /dev/vdb; the guest agent mounts it at /workspace with nodev,nosuid. The build worker must write its artifact inside /workspace/forgeos.

## Host lifecycle and security behavior

The host API is HTTPS-only at the transport layer and uses TLS 1.3 plus a dedicated bearer token. It signs provisioning attestations, state observations, and termination acknowledgements with Ed25519.

Each VM receives a dedicated cgroup v2 group with memory.max (guest RAM plus bounded VMM overhead), memory.swap.max=0, memory.oom.group=1, cpu.max, pids.max, and io.max. The host continuously moves matching kvm-pit kernel timer threads into the VM cgroup; provisioning evidence fails if the VMM is outside its cgroup, and a timer-thread placement failure tears down active VMs. The jailer starts Firecracker under a non-root per-instance UID/GID, a dedicated PID namespace, and a dedicated network namespace.

The VM rootfs, kernel, and workspace images live inside a fixed-size LUKS2-encrypted ephemeral volume. Egress is default-deny. Only reviewed public IPv4 CIDRs on TCP/443 and configured public DNS resolver IPs on UDP/TCP 53 are permitted. Private, loopback, link-local, multicast, and metadata destinations are rejected. Host input from the VM veth is dropped.

The host waits for the guest to verify the signed bootstrap, redeem its one-use credential, verify the immutable job snapshot digest, apply its guest pids limit, and mount the encrypted workspace before attesting provisioning. Firecracker default seccomp filters remain enabled; the guest serial UART is disabled and host stdout/stderr are discarded to avoid guest-controlled unbounded log output.

Teardown first kills the VM cgroup. It refuses to detach network or disk resources while any cgroup process remains. It then removes nftables rules, veth/network namespace, KVM ACL, unmounts encrypted storage, closes the LUKS mapper, and removes the cgroup. The state API only reports stopped after the runtime cleanup succeeds. A one-second expiry reaper enforces wall-clock deadlines; startup recovery destroys all previous instances rather than resuming them.

## Build and verification

    cd worker-host
    go test -race ./...
    go vet ./...
    go build -trimpath -ldflags="-s -w" ./cmd/forgeos-host-agent ./cmd/forgeos-guest-agent

GitHub Actions runs gofmt, race-enabled tests, vet, and compilation. These checks do not prove that KVM, cgroup, nftables, LUKS, jailer, vsock, crash recovery, or guest image behavior works on the production kernel. Run the privileged-host integration suite and an independent security review before registering any host as trusted.

Android builds must remain disabled until host enforcement, guest runtime, scheduler lifecycle, signing isolation, and production teardown have all been independently verified.