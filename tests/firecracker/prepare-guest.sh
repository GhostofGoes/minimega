#!/usr/bin/env bash
#
# Build the Firecracker guest images for smoke.sh from artifacts that are
# already downloaded. This script downloads nothing.
#
# Usage: sudo prepare-guest.sh <workdir>
#
# <workdir> must contain:
#   vmlinux          an uncompressed x86_64 guest kernel (ELF)
#   rootfs.squashfs  a guest root filesystem without a partition table
#
# The script writes these files to <workdir>:
#   rootfs.ext4      1 GiB ext4 image of the root filesystem
#   rootfs.qcow2     the same filesystem in qcow2 format
#   rootfs-part.raw  1.2 GiB raw image; partition 1 holds the same filesystem
#
# Environment:
#   MINICCC  miniccc binary to put in /usr/local/bin (default: bin/miniccc)

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <workdir>" >&2
	exit 2
fi

if [[ $EUID -ne 0 ]]; then
	echo "FAIL: run $0 as root, so that the image keeps the file owners" >&2
	exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "${script_dir}/../.." && pwd)"

workdir="$(cd "$1" && pwd)"
miniccc="${MINICCC:-${root_dir}/bin/miniccc}"

for f in "${workdir}/vmlinux" "${workdir}/rootfs.squashfs" "${miniccc}"; do
	if [[ ! -s "$f" ]]; then
		echo "FAIL: $f is missing or empty" >&2
		exit 1
	fi
done

for b in unsquashfs mkfs.ext4 qemu-img sfdisk truncate dd; do
	if ! command -v "$b" >/dev/null; then
		echo "FAIL: $b is not installed" >&2
		exit 1
	fi
done

tree="${workdir}/rootfs-tree"
ext4="${workdir}/rootfs.ext4"
qcow2="${workdir}/rootfs.qcow2"
part="${workdir}/rootfs-part.raw"

rm -rf "$tree"
rm -f "$ext4" "$qcow2" "$part"

echo "unpack ${workdir}/rootfs.squashfs"
unsquashfs -no-progress -d "$tree" "${workdir}/rootfs.squashfs" >/dev/null

echo "install ${miniccc} as /usr/local/bin/miniccc"
install -D -o root -g root -m 0755 "$miniccc" "${tree}/usr/local/bin/miniccc"

echo "build ${ext4}"
truncate -s 1G "$ext4"
mkfs.ext4 -q -F -L rootfs -d "$tree" "$ext4"

echo "build ${qcow2}"
qemu-img convert -f raw -O qcow2 "$ext4" "$qcow2"

# One DOS partition from sector 2048 (1 MiB) to the end of the image.
echo "build ${part}"
truncate -s 1228M "$part"
printf 'label: dos\nstart=2048, type=83\n' | sfdisk --quiet "$part"
dd if="$ext4" of="$part" bs=1M seek=1 conv=notrunc,sparse status=none

rm -rf "$tree"

ls -ls "$workdir"
qemu-img info "$qcow2"
sfdisk --dump "$part"
