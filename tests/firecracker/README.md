# Firecracker functional tests

These scripts boot real Firecracker VMs through minimega. They check the VM
lifecycle, the network, cc over vsock, the disk paths, and the cleanup of host
objects.

The GitHub Actions workflow
[`.github/workflows/firecracker.yml`](../../.github/workflows/firecracker.yml)
runs them on a hosted x86_64 Ubuntu 24.04 runner. The job runs two times:

- `xfs`: the Firecracker directory is on XFS with reflink. Each VM gets a
  reflink copy of the cached disk.
- `ext4`: the Firecracker directory is on ext4. Each VM gets a device-mapper
  snapshot of the cached disk.

The workflow installs Firecracker v1.17.0. It downloads a guest kernel and an
Ubuntu root filesystem from the Firecracker CI artifact bucket and verifies
their SHA-256 sums. When a test fails, the workflow uploads the minimega log
and the VM logs as an artifact.

## Files

| File | Use |
|---|---|
| `prepare-guest.sh` | Builds `rootfs.ext4`, `rootfs.qcow2`, and `rootfs-part.raw` from a kernel and a squashfs root filesystem. It adds miniccc and a systemd unit that starts `miniccc -family vsock -port 9002`. It downloads nothing. |
| `smoke.sh` | Runs the checks against a running minimega. |

## Guest network addresses

The guest root filesystem sets the address of each NIC from its MAC address.
A MAC `06:00:AA:BB:CC:DD` gives the address `AA.BB.CC.DD/30`. `smoke.sh` gives
each VM a MAC in its own `/30` and adds the other address of that `/30` to a
host tap.

## Run the tests on a Linux host

Use a Linux host with KVM that you can change. The tests run as root, and they
create taps, network namespaces, loop devices, and device-mapper targets.

1. Install the packages:

   ```bash
   sudo apt-get install build-essential dnsmasq iproute2 isc-dhcp-client libpcap-dev \
     ntfs-3g openssh-client openvswitch-switch qemu-kvm qemu-utils squashfs-tools \
     e2fsprogs xfsprogs acl dmsetup fdisk iputils-ping
   ```

2. Install `firecracker` and `jailer` v1.17.0 as `/usr/local/bin/firecracker`
   and `/usr/local/bin/jailer`, with owner `root` and mode `0755`.

3. Make a work directory. Put the guest kernel in it as `vmlinux` and the
   squashfs root filesystem in it as `rootfs.squashfs`. The workflow file
   gives the URLs and the SHA-256 sums.

4. Build minimega and miniccc from the repository root:

   ```bash
   source scripts/env.bash
   ./scripts/version.bash
   go build -o bin/minimega ./cmd/minimega
   CGO_ENABLED=0 go build -o bin/miniccc ./cmd/miniccc
   ```

5. Build the guest images:

   ```bash
   sudo MINICCC="$PWD/bin/miniccc" tests/firecracker/prepare-guest.sh <workdir>
   ```

6. Make the Firecracker directory `/var/lib/mmfc`. The directory and its
   parent directories must not be writable by the group or by other users.
   The directory must not be on a `nodev` or `noexec` mount.

7. Start minimega:

   ```bash
   sudo bin/minimega -nostdin -base /tmp/mm -firecracker-dir /var/lib/mmfc \
     -level debug -logfile /tmp/mm.log &
   ```

8. Run the checks. Set `FS` to the filesystem of `/var/lib/mmfc`, `xfs` or
   `ext4`:

   ```bash
   sudo FS=ext4 tests/firecracker/smoke.sh <workdir>
   ```

The checks use VLAN `LAN`, the host tap `mmfc_host`, and the addresses in
`172.16.0.0/28`. The cc checks put one file in the minimega files directory
(`<base>/files`) and remove it at the end. Use a minimega instance that has no
other VMs. To use other paths, set `MM`, `MM_BASE`, `MM_LOG`, `MM_FILES`, and
`FC_DIR`.
