#!/usr/bin/env bash
#
# Functional checks for Firecracker VMs against a running minimega.
#
# Usage: sudo -E smoke.sh <workdir>
#
# <workdir> holds the files from prepare-guest.sh: vmlinux, rootfs.qcow2, and
# rootfs-part.raw.
#
# Environment:
#   FS       xfs or ext4: the filesystem of FC_DIR (required)
#   MM       minimega binary (default: bin/minimega)
#   MM_BASE  minimega -base (default: /tmp/mm)
#   MM_LOG   minimega -logfile (default: /tmp/mm.log)
#   FC_DIR   minimega -firecracker-dir (default: /var/lib/mmfc)
#
# Guest addresses: the guest root filesystem runs fcnet-setup.sh from the
# Firecracker CI images. It reads a MAC of the form 06:00:AA:BB:CC:DD, sets
# the address AA.BB.CC.DD/30 on that NIC, and adds no routes. So each guest
# gets its own /30, and the host tap holds the other address of each /30:
#
#   VM    MAC                guest        host tap
#   fc1   06:00:ac:10:00:02  172.16.0.2   172.16.0.1/30
#   fc2   06:00:ac:10:00:06  172.16.0.6   172.16.0.5/30
#   fc3   06:00:ac:10:00:0a  172.16.0.10  172.16.0.9/30
#   fc4   06:00:ac:10:00:0e  172.16.0.14  172.16.0.13/30

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <workdir>" >&2
	exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "${script_dir}/../.." && pwd)"

WORKDIR="$(cd "$1" && pwd)"
FS="${FS:-}"
MM="${MM:-${root_dir}/bin/minimega}"
MM_BASE="${MM_BASE:-/tmp/mm}"
MM_LOG="${MM_LOG:-/tmp/mm.log}"
FC_DIR="${FC_DIR:-/var/lib/mmfc}"

KERNEL="${WORKDIR}/vmlinux"
QCOW2="${WORKDIR}/rootfs.qcow2"
PART="${WORKDIR}/rootfs-part.raw"

VLAN=LAN
BRIDGE=mega_bridge
HOST_TAP=mmfc_host
BEACON="the miniature beacons of gondor have been lit, it's a minifire!"
BANNER="minifire: Firecracker microVMs for minimega"

TMP="$(mktemp -d)"
INJECT_LOOP=""
INJECT_MNT=""

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

step() {
	echo
	echo "==== $*"
}

cleanup() {
	local rc=$?

	if [[ -n "$INJECT_MNT" ]] && mountpoint -q "$INJECT_MNT"; then
		umount "$INJECT_MNT" || true
	fi
	if [[ -n "$INJECT_LOOP" ]]; then
		losetup -d "$INJECT_LOOP" || true
	fi

	if [[ $rc -ne 0 ]]; then
		echo
		echo "==== last 50 lines of ${MM_LOG}"
		tail -n 50 "$MM_LOG" || true
	fi

	rm -rf "$TMP"
	exit "$rc"
}
trap cleanup EXIT

# mm runs one minimega command. minimega -e exits 0 even when the command
# fails, so mm returns 1 when the error output has an "Error (host)" line.
mm() {
	local rc=0
	local out

	out="$("$MM" -base "$MM_BASE" -e "$*" 2>"${TMP}/mm.err")" || rc=$?
	if [[ $rc -ne 0 ]] || grep -q 'Error (' "${TMP}/mm.err"; then
		[[ -n "$out" ]] && printf '%s\n' "$out" >&2
		cat "${TMP}/mm.err" >&2
		echo "minimega command failed: $*" >&2
		return 1
	fi

	[[ -n "$out" ]] && printf '%s\n' "$out"
	return 0
}

# vm_field prints one vm info column of one VM.
vm_field() {
	mm ".annotate false .headers false .csv true .columns $2 .filter name=$1 vm info" | head -n 1 | tr -d '[:space:]'
}

vm_id() {
	local id
	id="$(vm_field "$1" id)"
	[[ "$id" =~ ^[0-9]+$ ]] || fail "no VM ID for $1: '$id'"
	echo "$id"
}

vm_absent() {
	[[ -z "$(vm_field "$1" name 2>/dev/null)" ]]
}

state_is() {
	[[ "$(vm_field "$1" state 2>/dev/null)" == "$2" ]]
}

# wait_for runs a command once each second until it succeeds or the timeout
# (seconds) passes.
wait_for() {
	local timeout=$1 desc=$2
	shift 2

	local deadline=$((SECONDS + timeout))
	until "$@"; do
		if ((SECONDS >= deadline)); then
			fail "$desc: not true after ${timeout}s"
		fi
		sleep 1
	done
}

wait_state() {
	local name=$1 state=$2 timeout=$3
	if ! wait_for_quiet "$timeout" state_is "$name" "$state"; then
		echo "vm info for ${name}:" >&2
		mm ".filter name=${name} vm info" >&2 || true
		fail "${name} is not ${state} after ${timeout}s (state: $(vm_field "$name" state || true))"
	fi
}

# wait_for_quiet is wait_for, but returns 1 at the timeout.
wait_for_quiet() {
	local timeout=$1
	shift

	local deadline=$((SECONDS + timeout))
	until "$@"; do
		if ((SECONDS >= deadline)); then
			return 1
		fi
		sleep 1
	done
}

ping_ok() {
	ping -c 1 -W 1 "$1" >/dev/null 2>&1
}

ping_fails() {
	! ping_ok "$1"
}

guest_mac() {
	printf '06:00:ac:10:00:%02x' $((4 * $1 - 2))
}

guest_ip() {
	echo "172.16.0.$((4 * $1 - 2))"
}

host_ip() {
	echo "172.16.0.$((4 * $1 - 3))"
}

# instance_disk prints the host path of disk 0 of VM id: a file on xfs, a
# device-mapper snapshot on ext4.
instance_disk() {
	local id=$1
	if [[ "$FS" == xfs ]]; then
		echo "${FC_DIR}/vm/${id}/disk-0.raw"
		return
	fi

	local name
	name="$(dmsetup ls | awk -v re="^mm-fc-[0-9a-f]+-${id}-0\$" '$1 ~ re {print $1}')"
	[[ -n "$name" ]] || fail "no device-mapper target for VM ${id}"
	echo "/dev/mapper/${name}"
}

base_config() {
	mm "clear vm config"
	mm "vm config vcpus 1"
	mm "vm config memory 256"
	mm "vm config kernel ${KERNEL}"
	mm "vm config append root=/dev/vda"
	mm "vm config disk ${QCOW2}"
	mm "vm config snapshot true"
	mm "vm config backchannel false"
}

# leftovers prints one line for each host object that a flushed Firecracker
# VM left behind.
leftovers() {
	local ns dm port
	ns="$(ip netns list | awk '{print $1}' | grep '^mm-fc-' || true)"
	[[ -z "$ns" ]] || echo "netns: ${ns//$'\n'/ }"

	dm="$(dmsetup ls 2>/dev/null | awk '{print $1}' | grep '^mm-fc-' || true)"
	[[ -z "$dm" ]] || echo "device-mapper targets: ${dm//$'\n'/ }"

	if [[ -d "${FC_DIR}/vm" ]] && [[ -n "$(find "${FC_DIR}/vm" -mindepth 1 -maxdepth 1)" ]]; then
		echo "instance directories: $(find "${FC_DIR}/vm" -mindepth 1 -maxdepth 1 | tr '\n' ' ')"
	fi

	if [[ -d "${FC_DIR}/jail" ]] && [[ -n "$(find "${FC_DIR}/jail" -mindepth 2 -maxdepth 2)" ]]; then
		echo "jails: $(find "${FC_DIR}/jail" -mindepth 2 -maxdepth 2 | tr '\n' ' ')"
	fi

	local loops
	loops="$(losetup -a | grep -F "${FC_DIR}/" || true)"
	[[ -z "$loops" ]] || echo "loop devices: ${loops//$'\n'/ }"

	port="$(ovs-vsctl list-ports "$BRIDGE" 2>/dev/null | grep -vx "$HOST_TAP" || true)"
	[[ -z "$port" ]] || echo "OVS ports on ${BRIDGE}: ${port//$'\n'/ }"
}

no_leftovers() {
	[[ -z "$(leftovers)" ]]
}

check_clean() {
	if ! wait_for_quiet 30 no_leftovers; then
		leftovers >&2
		fail "flushed VMs left host objects behind"
	fi
	echo "no netns, device-mapper targets, instance directories, jails, loop devices, or OVS ports are left"
}

all_quit() {
	local s
	s="$(mm ".annotate false .headers false .csv true .columns state vm info" | tr -d '[:blank:]' | grep -v '^$' | grep -vx QUIT || true)"
	[[ -z "$s" ]]
}

no_vms() {
	[[ -z "$(mm ".annotate false .headers false .csv true .columns name vm info" | tr -d '[:space:]')" ]]
}

kill_flush_all() {
	mm "vm kill all"
	wait_for 60 "all VMs are QUIT" all_quit
	mm "vm flush"
	wait_for 30 "vm info has no VMs" no_vms
}

case "$FS" in
xfs | ext4) ;;
*) fail "set FS to xfs or ext4" ;;
esac

[[ $EUID -eq 0 ]] || fail "run $0 as root"
for f in "$MM" "$KERNEL" "$QCOW2" "$PART"; do
	[[ -s "$f" ]] || fail "$f is missing or empty"
done
"$MM" -base "$MM_BASE" -e version >/dev/null || fail "minimega does not answer on ${MM_BASE}"

# ---------------------------------------------------------------------------
step "1. check reports Firecracker ${FS}"

start_line=$(($(wc -l <"$MM_LOG") + 1))
mm "check"
sleep 1
tail -n "+${start_line}" "$MM_LOG" >"${TMP}/check.log"
grep -E 'firecracker|jailer|cgroup version|/dev/kvm|reflink|loop-control|mapper/control|qemu-img|dmsetup|setfacl' "${TMP}/check.log" || true
grep -qE 'firecracker and jailer versions match: v?1\.17\.0' "${TMP}/check.log" ||
	fail "check does not report matching firecracker and jailer v1.17.0"
if grep -q 'firecracker unavailable' "${TMP}/check.log"; then
	fail "check reports that firecracker is unavailable"
fi
want_reflink=false
[[ "$FS" == xfs ]] && want_reflink=true
grep -qF "${FC_DIR} filesystem: ${FS}, reflink: ${want_reflink}" "${TMP}/check.log" ||
	fail "check does not report ${FC_DIR} as ${FS} with reflink ${want_reflink}"

# ---------------------------------------------------------------------------
step "2. host tap on VLAN ${VLAN}"

mm "tap create ${VLAN} ip $(host_ip 1)/30 ${HOST_TAP}"
for i in 2 3 4; do
	ip addr add "$(host_ip "$i")/30" dev "$HOST_TAP"
done
ip link set "$HOST_TAP" up
ip -br addr show dev "$HOST_TAP"

# ---------------------------------------------------------------------------
step "3. launch fc1, fc2, and fc3 from rootfs.qcow2"

base_config
for i in 1 2 3; do
	mm "vm config net ${VLAN},$(guest_mac "$i")"
	mm "vm launch firecracker fc${i}"
	wait_state "fc${i}" BUILDING 60
done
mm ".columns name,state,type,vlan,mac,tap vm info"

# ---------------------------------------------------------------------------
step "4. start fc1, fc2, and fc3"

mm "vm start all"
for i in 1 2 3; do
	wait_state "fc${i}" RUNNING 30
done
for i in 1 2 3; do
	wait_for 90 "fc${i} answers ping at $(guest_ip "$i")" ping_ok "$(guest_ip "$i")"
	echo "fc${i} answers at $(guest_ip "$i")"
done

# ---------------------------------------------------------------------------
step "5. stop and resume fc1"

mm "vm stop fc1"
wait_state fc1 PAUSED 10
wait_for 5 "ping to paused fc1 fails" ping_fails "$(guest_ip 1)"
echo "paused fc1 does not answer"
mm "vm start fc1"
wait_state fc1 RUNNING 10
wait_for 30 "resumed fc1 answers ping" ping_ok "$(guest_ip 1)"
echo "resumed fc1 answers"

# ---------------------------------------------------------------------------
step "6. kill and relaunch fc2"

mm "vm kill fc2"
wait_state fc2 QUIT 30
mm "vm start fc2"
wait_state fc2 RUNNING 30
wait_for 90 "relaunched fc2 answers ping" ping_ok "$(guest_ip 2)"
echo "relaunched fc2 answers"

# ---------------------------------------------------------------------------
step "7. console logs"

for i in 1 2 3; do
	id="$(vm_id "fc${i}")"
	console="${FC_DIR}/vm/${id}/console.log"
	[[ -s "$console" ]] || fail "${console} of fc${i} is missing or empty"
	grep -m 1 'Linux version' "$console" || fail "${console} of fc${i} has no 'Linux version' line"
done

# ---------------------------------------------------------------------------
step "8. disk path for ${FS}"

mm "disk cache"
qcow2_entries="$(mm ".annotate false .headers false .csv true disk cache" | awk -F, -v src="$QCOW2" '$2 == src && $3 == "qcow2"')"
[[ "$(grep -c . <<<"$qcow2_entries")" -eq 1 ]] ||
	fail "disk cache has $(grep -c . <<<"$qcow2_entries") entries for ${QCOW2}, not 1"
inuse="$(awk -F, '{print $6}' <<<"$qcow2_entries" | tr -d '[:space:]')"
[[ "$inuse" == 3 ]] || fail "the cache entry of ${QCOW2} has ${inuse} users, not 3"

for i in 1 2 3; do
	id="$(vm_id "fc${i}")"
	if [[ "$FS" == xfs ]]; then
		disk="${FC_DIR}/vm/${id}/disk-0.raw"
		[[ -f "$disk" && ! -L "$disk" ]] || fail "${disk} of fc${i} is not a regular file"
		[[ "$(stat -c %u "$disk")" != 0 ]] || fail "${disk} of fc${i} is owned by root, not by the VM uid"
		frag="$(filefrag -v "$disk" 2>&1 || true)"
		if grep -q shared <<<"$frag"; then
			echo "fc${i}: ${disk} has shared (reflink) extents"
		else
			echo "fc${i}: filefrag shows no shared extents for ${disk}"
		fi
	else
		disk="$(instance_disk "$id")"
		[[ -b "$disk" ]] || fail "${disk} of fc${i} is not a block device"
		[[ -f "${FC_DIR}/vm/${id}/disk-0.cow" ]] || fail "fc${i} has no copy-on-write file"
		echo "fc${i}: ${disk}"
	fi
done
if [[ "$FS" == ext4 ]]; then
	dmsetup ls | grep '^mm-fc-'
fi

# ---------------------------------------------------------------------------
step "9. snapshot false refuses a qcow2 image"

mm "clear vm config net"
mm "vm config snapshot false"
launch_out="$(mm "vm launch firecracker bad1" 2>&1)" || true
echo "$launch_out"
wait_state bad1 ERROR 30
tags="$(mm ".annotate false .headers false .columns tags .filter name=bad1 vm info" || true)"
echo "bad1 tags: ${tags}"
grep -qi raw <<<"${launch_out} ${tags}" || fail "the error for bad1 does not mention raw"
mm "vm flush"
wait_for 30 "bad1 is flushed" vm_absent bad1
mm "vm config snapshot true"

# ---------------------------------------------------------------------------
step "10. inject a file into a partitioned raw image"

inject_src="${TMP}/minifire-test"
echo "minifire inject test $(date +%s) $$" >"$inject_src"

mm "vm config disk ${PART}"
mm "vm config append root=/dev/vda1"
mm "vm config inject 1 ${inject_src}:/etc/minifire-test"
mm "vm config net ${VLAN},$(guest_mac 4)"
mm "vm launch firecracker fc4"
wait_state fc4 BUILDING 120
mm "vm start fc4"
wait_state fc4 RUNNING 30
wait_for 90 "fc4 answers ping" ping_ok "$(guest_ip 4)"
echo "fc4 answers at $(guest_ip 4)"
mm "vm kill fc4"
wait_state fc4 QUIT 30

id="$(vm_id fc4)"
disk="$(instance_disk "$id")"
INJECT_LOOP="$(losetup -f -P -r --show "$disk")"
wait_for 10 "${INJECT_LOOP}p1 exists" test -b "${INJECT_LOOP}p1"
INJECT_MNT="${TMP}/mnt"
mkdir -p "$INJECT_MNT"
mount -o ro,noload "${INJECT_LOOP}p1" "$INJECT_MNT"
cmp "$inject_src" "${INJECT_MNT}/etc/minifire-test" ||
	fail "/etc/minifire-test in the disk of fc4 does not match ${inject_src}"
echo "fc4 disk ${disk} has /etc/minifire-test"
umount "$INJECT_MNT"
INJECT_MNT=""
losetup -d "$INJECT_LOOP"
INJECT_LOOP=""

mm "clear vm config inject"
mm "vm flush"
wait_for 30 "fc4 is flushed" vm_absent fc4

# ---------------------------------------------------------------------------
step "11. launch and start 20 VMs"

base_config
mm "clear vm config net"
mm "vm config memory 128"

"$MM" -base "$MM_BASE" -e "vm launch firecracker scale[1-20]" >"${TMP}/launch.out" 2>&1 &
launch_pid=$!

answered=0
probes=0
while kill -0 "$launch_pid" 2>/dev/null; do
	probes=$((probes + 1))
	if timeout 5 "$MM" -base "$MM_BASE" -e "vm info summary" >/dev/null 2>&1 && kill -0 "$launch_pid" 2>/dev/null; then
		answered=$((answered + 1))
		break
	fi
	sleep 1
done
if ! wait "$launch_pid"; then
	cat "${TMP}/launch.out" >&2
	fail "vm launch firecracker scale[1-20] did not exit 0"
fi
cat "${TMP}/launch.out"
if grep -q 'Error (' "${TMP}/launch.out"; then
	fail "vm launch firecracker scale[1-20] failed"
fi
[[ $answered -ge 1 ]] || fail "vm info did not answer within 5s during the launch (${probes} probes)"
echo "vm info answered during the launch"

scale_running() {
	local n
	n="$(mm ".annotate false .headers false .csv true .columns name,state vm info" | grep -c '^scale[0-9]*,RUNNING' || true)"
	[[ "$n" -eq 20 ]]
}

mm "vm start all"
if ! wait_for_quiet 120 scale_running; then
	mm ".columns name,state,tags vm info" >&2 || true
	fail "not all 20 scale VMs are RUNNING after 120s"
fi
echo "20 scale VMs are RUNNING"

# ---------------------------------------------------------------------------
step "12. kill and flush all VMs"

kill_flush_all
check_clean

# ---------------------------------------------------------------------------
step "13. minifire"

banner="$(mm "minifire")"
echo "$banner"
grep -qF "$BANNER" <<<"$banner" || fail "minifire does not print the banner"

start_line=$(($(wc -l <"$MM_LOG") + 1))
base_config
mm "clear vm config net"
mm "vm launch firecracker minifire"
beacon_lit() {
	tail -n "+${start_line}" "$MM_LOG" | grep -qF "$BEACON"
}
wait_for 30 "the log has the beacon message" beacon_lit
echo "the log has the beacon message"
kill_flush_all
check_clean

mm "tap delete ${HOST_TAP}"

echo
echo "PASS: all Firecracker smoke checks passed on ${FS}"
