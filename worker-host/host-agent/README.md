# Privileged host-agent installation

Install the immutable host-agent binary at `/usr/local/sbin/forgeos-host-agent`, this unit at `/etc/systemd/system/forgeos-host-agent.service`, and a root-only environment file at `/etc/forgeos/host-agent.env` (mode 0600).

The host agent must run on a dedicated Linux host with KVM, Firecracker and jailer installed from the same pinned release, cgroup v2, nftables, iproute2, cryptsetup, ext4 tools, ACL tools, and a block-backed filesystem for `StateDir`. Do not run it inside Docker or another container. Disable host swap, KSM, and SMT. Keep host kernel and microcode patched.

The unit uses `Delegate=yes`. Install the accompanying `forgeos-host.slice` and configure `CgroupParent` in the JSON config as `forgeos-host.slice/forgeos-host-agent.service/instances`. The slice enables CPU, memory, task/pids, and I/O accounting so the service cgroup receives those controllers. At first provisioning, the agent moves its own service process into a control child, enables cpu/memory/pids/io controllers in the service cgroup, and creates the empty `instances` parent. VM cgroups are children of that parent. Do not put the host agent process itself in the instances cgroup.

Recommended host runtime paths:
- `StateDir=/var/lib/forgeos-host-agent` (mode 0700, on a block-backed filesystem)
- `ChrootBase=/srv/forgeos-jailer` (mode 0700)
- `CgroupParent=system.slice/forgeos-host-agent.service/instances`

The service needs root because it configures KVM ACLs, cgroups, namespaces, TAP/veth networking, nftables, encrypted disks, mounts, and the Firecracker jailer. The host attestation private key and TLS private key remain on the host, root-owned and mode 0600. Never copy either private key into the guest image. The guest image receives only the Ed25519 public key.

`PLATFORM_WORKER_TOKEN` must exactly match the platform's `BUILD_WORKER_SHARED_SECRET`. `HOST_AGENT_TOKEN` is a separate random bearer token for the provider-facing host API. Do not reuse either as a guest credential. Keep `ENABLE_ANDROID_BUILDS=false` until live host and guest isolation has been independently validated and a separate release-signing service exists.

After installing the files, run `systemctl daemon-reload`, inspect the effective unit and environment permissions, then enable the service. Do not start it on a production host until the host config contains pinned image digests, kernel paths, egress policies, DNS resolvers, TLS identity, and the Ed25519 attestation key.
