#!/bin/bash
# Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
# rights in this software.
#
# Build the tiny KVM guest used by the live integration tests: a stock Ubuntu
# kernel plus a busybox initramfs carrying miniccc, minirouter, and protonuke.
#
# This script runs INSIDE the minimega Docker image under test so that the
# guest agents (miniccc, minirouter, protonuke) are byte-for-byte the binaries
# shipped in that image. It writes two files to the output directory:
#
#   live.kernel  - the guest kernel (vmlinuz)
#   live.initrd  - a gzip-compressed cpio initramfs
#
# Usage (from the repository root):
#
#   docker run --rm -v "$PWD/tests/live/image:/src:ro" -v "$OUT:/out" \
#     <minimega image> bash /src/build.sh /out

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:?usage: build.sh <output dir>}"
MM_BIN="${MM_BIN:-/opt/minimega/bin}"
WORK="$(mktemp -d)"
ROOT="${WORK}/rootfs"
KROOT="${WORK}/kernel"

# Kernel modules the guest may need. Modules that are built into the kernel
# are skipped automatically. Order does not matter; dependencies are resolved
# with modprobe --show-depends.
MODULES=(
	# PCI, virtio, and NICs used by the topology
	virtio_pci virtio_net virtio_console virtio_blk e1000 e1000e
	# block devices: ide/ahci disks and USB storage for "vm hotplug"
	ata_piix ahci sd_mod sr_mod usb_storage ehci_pci uhci_hcd xhci_pci
	# minirouter firewall support (iptables-legacy)
	ip_tables iptable_filter x_tables xt_conntrack nf_conntrack xt_tcpudp
	ipt_REJECT nf_reject_ipv4 xt_state
)

log() { echo "[build.sh] $*" >&2; }

export DEBIAN_FRONTEND=noninteractive

log "installing build dependencies"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
	busybox bird dnsmasq-base iptables iproute2 kmod cpio gzip \
	ca-certificates >/dev/null

# --- kernel ------------------------------------------------------------------

# Resolve the concrete kernel package behind the "virtual" metapackage and
# unpack it without running maintainer scripts (no initramfs-tools needed).
KPKG="$(apt-cache depends linux-image-virtual | awk '/Depends: linux-image-[0-9]/ {print $2; exit}')"
KVER="${KPKG#linux-image-}"
log "using kernel ${KVER}"

mkdir -p "${KROOT}"
(
	cd "${WORK}"
	apt-get download -qq "linux-image-${KVER}" "linux-modules-${KVER}"
	for deb in ./*.deb; do dpkg-deb -x "${deb}" "${KROOT}"; done
)
depmod -b "${KROOT}" "${KVER}"

# copy_bin <path> [dest]: copy a dynamically linked binary and its libraries
copy_bin() {
	local src="$1" dst="${2:-$1}"
	mkdir -p "$(dirname "${ROOT}${dst}")"
	rm -f "${ROOT}${dst}"
	cp -L "${src}" "${ROOT}${dst}"
	copy_libs "${src}"
}

copy_libs() {
	local lib
	for lib in $(ldd "$1" 2>/dev/null | grep -o '/[^ ]*' | sort -u); do
		[[ -e "${ROOT}${lib}" ]] && continue
		mkdir -p "$(dirname "${ROOT}${lib}")"
		cp -L "${lib}" "${ROOT}${lib}"
	done
}

# --- rootfs skeleton ---------------------------------------------------------

log "assembling rootfs"
mkdir -p "${ROOT}"/{bin,sbin,usr/bin,usr/sbin,usr/local/sbin,etc/init.d,dev,proc,sys,tmp,run,root,var/log,var/run,var/lib/misc,lib/modules/live,usr/share/udhcpc}

# busybox provides init, sh, udhcpc, ping, wget, nslookup, nc, and friends.
# Use the dynamically linked build: the static one crashes in glibc's
# resolver (wget segfaults).
copy_bin /bin/busybox /bin/busybox
for applet in $("${ROOT}/bin/busybox" --list-full); do
	[[ -e "${ROOT}/${applet}" ]] || ln -s /bin/busybox "${ROOT}/${applet}"
done
ln -sf bin/busybox "${ROOT}/init"

# minimega guest agents, straight from the image under test. "router commit"
# runs "minirouter -u ..." through miniccc, so minirouter must be on PATH;
# minirouter in turn expects miniccc at /miniccc by default.
copy_bin "${MM_BIN}/miniccc" /usr/bin/miniccc
copy_bin "${MM_BIN}/minirouter" /usr/bin/minirouter
copy_bin "${MM_BIN}/protonuke" /usr/bin/protonuke
ln -s /usr/bin/miniccc "${ROOT}/miniccc"
ln -s /usr/bin/minirouter "${ROOT}/minirouter"

# real iproute2 (minirouter relies on "ip addr add/del")
copy_bin /usr/bin/ip /sbin/ip
ln -sf /sbin/ip "${ROOT}/bin/ip"
ln -sf /sbin/ip "${ROOT}/usr/bin/ip"

# routing daemons used by minirouter
copy_bin /usr/sbin/bird /usr/sbin/bird
copy_bin /usr/sbin/bird6 /usr/sbin/bird6
copy_bin /usr/sbin/dnsmasq /usr/sbin/dnsmasq

# iptables (legacy backend; the nft backend needs nf_tables and a newer setup)
copy_bin /usr/sbin/xtables-legacy-multi /usr/sbin/xtables-legacy-multi
for name in iptables iptables-save iptables-restore; do
	ln -sf xtables-legacy-multi "${ROOT}/usr/sbin/${name}"
	ln -sf /usr/sbin/xtables-legacy-multi "${ROOT}/sbin/${name}"
done
XT_DIR="$(dirname "$(ls /usr/lib/x86_64-linux-gnu/xtables/libxt_standard.so)")"
mkdir -p "${ROOT}${XT_DIR}"
cp -a "${XT_DIR}"/libxt_*.so "${XT_DIR}"/libipt_*.so "${ROOT}${XT_DIR}/"
for so in "${ROOT}${XT_DIR}"/*.so; do copy_libs "${so}"; done

# glibc loads NSS modules with dlopen, so ldd does not report them
cp -L /lib/x86_64-linux-gnu/libnss_files.so.* "${ROOT}/lib/x86_64-linux-gnu/" 2>/dev/null || true

# --- kernel modules ----------------------------------------------------------

log "collecting kernel modules"
: > "${ROOT}/etc/modules.live"
declare -A seen=()
for mod in "${MODULES[@]}"; do
	while read -r kind path _; do
		[[ "${kind}" == "insmod" ]] || continue
		[[ -n "${seen[${path}]:-}" ]] && continue
		seen[${path}]=1
		name="$(basename "${path}")"
		cp "${path}" "${ROOT}/lib/modules/live/${name}"
		echo "${name}" >> "${ROOT}/etc/modules.live"
	done < <(modprobe -d "${KROOT}" -S "${KVER}" --show-depends "${mod}" 2>/dev/null || true)
done
log "bundled $(wc -l < "${ROOT}/etc/modules.live") modules"

# --- configuration -----------------------------------------------------------

install -m 0755 "${SRC}/rcS" "${ROOT}/etc/init.d/rcS"
install -m 0755 "${SRC}/udhcpc.script" "${ROOT}/usr/share/udhcpc/default.script"
install -m 0755 "${SRC}/run-miniccc" "${ROOT}/usr/local/sbin/run-miniccc"
install -m 0755 "${SRC}/run-minirouter" "${ROOT}/usr/local/sbin/run-minirouter"
install -m 0644 "${SRC}/inittab" "${ROOT}/etc/inittab"

cat > "${ROOT}/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
EOF
cat > "${ROOT}/etc/group" <<'EOF'
root:x:0:
dip:x:30:
nogroup:x:65534:
EOF
echo "hosts: files dns" > "${ROOT}/etc/nsswitch.conf"
echo "127.0.0.1 localhost" > "${ROOT}/etc/hosts"
: > "${ROOT}/etc/resolv.conf"
: > "${ROOT}/etc/fstab"
echo "minimega live test guest (kernel ${KVER})" > "${ROOT}/etc/motd"

# --- pack --------------------------------------------------------------------

mkdir -p "${OUT}"
cp "${KROOT}/boot/vmlinuz-${KVER}" "${OUT}/live.kernel"
(cd "${ROOT}" && find . -print0 | cpio --null -o -H newc --quiet | gzip -9) > "${OUT}/live.initrd"
chmod 0644 "${OUT}/live.kernel" "${OUT}/live.initrd"

log "kernel: $(du -h "${OUT}/live.kernel" | cut -f1), initrd: $(du -h "${OUT}/live.initrd" | cut -f1)"
rm -rf "${WORK}"
