# Immutable ForgeOS guest image

Bake the following root-owned, non-group/world-writable files into the approved ext4 rootfs image:

- /usr/local/sbin/forgeos-guest-agent
- /usr/local/bin/forgeos-build-worker
- /etc/forgeos/host-agent.pub
- /etc/forgeos/guest-agent.env
- /etc/systemd/system/forgeos-guest-agent.service

Install the unit, enable it, and verify that the guest boots into it automatically. The host public key must correspond to the Ed25519 public key paired with HOST_AGENT_SIGNING_KEY. The host agent sends a signed bootstrap over AF_VSOCK; no bootstrap credential or lease token is baked into the image.

The guest worker must be an immutable, root-owned executable. It receives only the snapshot path, artifact path, job ID, and attempt in its arguments/environment. It runs as UID/GID 10000 with supplementary groups cleared and PR_SET_NO_NEW_PRIVS enabled. It must not require root, capabilities, host secrets, or a privileged container socket.

The guest agent itself runs as root because it must verify the signed bootstrap, redeem the one-use credential over HTTPS, configure the guest pids cgroup, mount the encrypted workspace, and power off the guest. The build worker is launched as a separate child process and immediately drops privileges before exec.

Build the guest agent for the guest architecture with CGO disabled. Pin the worker binary, rootfs image digest, kernel image, and host public key as part of the worker image release process. Recompute the rootfs SHA-256 digest after every image change and update the host ImagePaths and scheduler imageDigests maps together.

The guest rootfs must include systemd, cgroup v2, the pids controller, ext4 mount support, networking, CA certificates, and the dependencies required by the build worker. The guest kernel must support AF_VSOCK and expose cgroup v2. The host attaches the encrypted workspace as /dev/vdb; the guest agent mounts it at /workspace.

The guest service must not restart after its one job. The VM is disposable: after the guest reports success/failure, the guest powers off and the host independently destroys the VM and its encrypted disk.
