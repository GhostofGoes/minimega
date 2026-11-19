#!/usr/bin/env bash
# Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
# rights in this software.
#
# SPIKE ONLY: not for merge.
#
# Find out whether a KVM state file that "vm save" writes on QEMU 6.2 restores
# on QEMU 11.1.3, with and without "vm config machine pc-i440fx-6.2".
#
#   sudo tests/live/spike-restore.sh <old image> <new image> [artifacts dir]
#
# Phases:
#   SAVE-OLD                boot a guest on the old image, write a marker, vm save
#   SAVE-OLD-PC             the same in parallel, with vm config machine pc
#   RESTORE-NEW-UNPINNED    restore the SAVE-OLD state on the new image, default machine
#   RESTORE-NEW-PINNED      the same, with vm config machine pc-i440fx-6.2
#   RESTORE-NEW-REWRITTEN   the same, from a copy whose header names pc-i440fx-6.2
#   RESTORE-NEW-PC-PINNED   restore the SAVE-OLD-PC state, machine pc-i440fx-6.2
#   CONTROL-NEW             save and restore on the new image only
#
# Requirements: Linux, root, Docker, /dev/kvm, and the openvswitch kernel module
# (the same as tests/live/run.sh).
#
# Environment:
#   SPIKE_OLD_IMAGE, SPIKE_NEW_IMAGE, SPIKE_ARTIFACTS   defaults for the arguments
#   SPIKE_PULL=0          use local images without pulling
#   SPIKE_GUEST_DIR       directory with a prebuilt live.kernel and live.initrd
#   SPIKE_MIN_UPTIME      guest uptime in seconds before each save (default 120)
#   SPIKE_LOGLEVEL        minimega log level (default debug)
#   SPIKE_FORCE=1         replace an existing container and base directory
#   SPIKE_KEEP=1          keep the base directory (state files) at exit
#
# The output ends with "RESULT key=value" lines. The exit status is 0 when every
# phase produced a result (a failed restore is a valid result), and 1 when the
# procedure could not run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OLD_IMAGE="${1:-${SPIKE_OLD_IMAGE:-}}"
NEW_IMAGE="${2:-${SPIKE_NEW_IMAGE:-}}"
ART_DIR="${3:-${SPIKE_ARTIFACTS:-${PWD}/spike-artifacts}}"

CONTAINER=minimega-spike
MM_BASE=/tmp/minimega-spike
MM_FILES="${MM_BASE}/files"
STAGE="${MM_FILES}/spike"
WRAP="${STAGE}/qemu-wrap"
QEMU_LOG="${STAGE}/qemu-stderr.log"
STATE_OLD="${MM_FILES}/spike-old.state"
STATE_OLD_PC="${MM_FILES}/spike-old-pc.state"
STATE_RW="${MM_FILES}/spike-old-rewritten.state"
STATE_CTL="${MM_FILES}/spike-ctl.state"
PINNED_MACHINE=pc-i440fx-6.2
OLD_PC_MACHINE=pc

VM_MAIN=spike
UUID_MAIN=5b1d0000-0000-4000-8000-00000000a5e1
VM_PC=spikepc
UUID_PC=5b1d0000-0000-4000-8000-00000000a5e2
VM="${VM_MAIN}"
UUID="${UUID_MAIN}"
MEMORY=512
MIN_UPTIME="${SPIKE_MIN_UPTIME:-120}"

QMP_TYPE='{ "execute": "qom-get", "arguments": { "path": "/machine", "property": "type" } }'
QMP_STATUS='{ "execute": "query-status" }'

QEMU_OLD=unknown
QEMU_NEW=unknown
MACHINE_OLD=unknown
MACHINE_OLD_PC=unknown
RES_UNPINNED=fail
DET_UNPINNED="not run"
RES_PINNED=fail
DET_PINNED="not run"
RES_RW=fail
DET_RW="not run"
RES_PC=fail
DET_PC="not run"
RES_CONTROL=fail
DET_CONTROL="not run"
RESULTS_PRINTED=0
OWN_BASE=0
OWN_CONTAINER=0

NS=""
DETAIL=""
CC_SEQ=0
CC_STDOUT=""
CC_STDERR=""
CC_EXIT=""
WAITED=0
MARKER=""
UPTIME=""
SAVED_UPTIME=""
OLD_MARKER=""
OLD_UPTIME=""
OLD_HEADER=unknown
PC_LAUNCHED=0
PC_LAUNCH_ERR=""
PC_MARKER=""
PC_UPTIME=""
PC_HEADER=unknown
MACHINE=""
HEADER=""

log() { echo "==> [$(date +%H:%M:%S)] $*"; }
phase() { echo; echo "==================== $* ===================="; }
die() { echo "ERROR: $*" >&2; exit 1; }

# oneline TEXT [LIMIT] joins text into one grep-friendly line without double quotes.
oneline() { printf '%s' "$1" | tr '\n\r\t"' "   '" | tr -s ' ' | sed 's/^ //; s/ $//' | cut -c "1-${2:-400}"; }

# use_vm NAMESPACE NAME UUID selects the namespace and VM that later commands use.
use_vm() { NS=$1; VM=$2; UUID=$3; }

# --- minimega commands ------------------------------------------------------

# The client reads MM_LOGLEVEL and MM_LOGFILE from the container, so set its
# level and log file explicitly: stdout keeps only the response.
mm() { timeout "${MM_TIMEOUT:-120}" docker exec "${CONTAINER}" minimega -level=error -logfile= -e "$1"; }

# mmrun runs one minimega command line, prints the response, and logs stdout
# and stderr. It fails on a non-zero exit or on minimega's "Error (<host>):"
# lines, and then also prints stderr. MM_QUIET=1 keeps it out of the console.
mmrun() {
    local out errf err rc=0
    errf="$(mktemp)"
    out="$(mm "$1" 2>"${errf}")" || rc=$?
    err="$(cat "${errf}")"
    rm -f "${errf}"
    if (( rc == 0 )) && grep -q '^Error (' <<<"${err}"; then
        rc=1
    fi
    {
        echo "mm[${NS}]> $1 (exit ${rc})"
        if [[ -n "${out}" ]]; then printf '%s\n' "${out}"; fi
        if [[ -n "${err}" ]]; then printf '%s\n' "${err}" | sed 's/^/stderr: /'; fi
    } >> "${ART}/commands.log"
    if [[ "${MM_QUIET:-0}" != "1" ]]; then
        echo "  mm> $1" >&2
        if [[ -n "${out}${err}" ]]; then printf '%s\n' "${out}" "${err}" | sed '/^$/d; s/^/      /' >&2; fi
    fi
    if [[ -n "${out}" ]]; then printf '%s\n' "${out}"; fi
    if (( rc != 0 )) && [[ -n "${err}" ]]; then printf '%s\n' "${err}"; fi
    return "${rc}"
}

# mmv runs a command in the phase namespace with bare CSV output.
mmv() { mmrun "namespace ${NS} .csv true .headers false .annotate false $1"; }

ns_run() { mmrun "namespace ${NS} $1"; }

# Parsers accept only the expected shape, so any other line reads as no value.
vm_state() {
    local out
    out="$(MM_QUIET=1 mmv ".columns state .filter name=${VM} vm info" || true)"
    grep -E '^[A-Z_]+$' <<<"${out}" | head -n 1 || true
}

qmp() { mmrun "namespace ${NS} .annotate false vm qmp ${VM} '$1'"; }

qmp_status() {
    local out
    out="$(MM_QUIET=1 qmp "${QMP_STATUS}" || true)"
    sed -n 's/^[[:space:]]*{.*"return".*"status": *"\([a-z-]*\)".*/\1/p' <<<"${out}" | head -n 1 || true
}

qmp_machine() {
    local out
    out="$(qmp "${QMP_TYPE}" || true)"
    sed -n 's/^[[:space:]]*{.*"return": *"\([^"]*\)".*/\1/p' <<<"${out}" | head -n 1 || true
}

# --- containers ---------------------------------------------------------------

# start_mm starts minimega from an image with the run.sh flags (no published ports).
start_mm() {
    local image=$1 label=$2
    log "starting ${CONTAINER} from ${image} (${label})"
    docker run -d \
        --name "${CONTAINER}" \
        --hostname minimega \
        --privileged \
        --cap-add ALL \
        -v /dev:/dev \
        -v /lib/modules:/lib/modules:ro \
        -v "${ART}/logs:/var/log/minimega" \
        -v "${MM_BASE}:${MM_BASE}" \
        -e MM_BASE="${MM_BASE}" \
        -e MM_FILEPATH="${MM_FILES}" \
        -e MM_LOGFILE="/var/log/minimega/minimega-${label}.log" \
        -e MM_LOGLEVEL="${SPIKE_LOGLEVEL:-debug}" \
        --health-cmd "mm version" \
        "${image}" >/dev/null || return 1
    OWN_CONTAINER=1
    for _ in $(seq 1 60); do
        if mm version >/dev/null 2>&1; then
            mm version
            return 0
        fi
        sleep 2
    done
    docker logs "${CONTAINER}" 2>&1 | tail -50
    return 1
}

# stop_mm stops the container and removes everything in the base directory but the files.
stop_mm() {
    local label=$1
    log "stopping ${CONTAINER} (${label})"
    docker logs "${CONTAINER}" > "${ART}/logs/container-${label}.log" 2>&1 || true
    docker stop -t 30 "${CONTAINER}" >/dev/null 2>&1 || true
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
    OWN_CONTAINER=0
    tar -C "${MM_BASE}" --exclude=./files -czf "${ART}/instance-${label}.tgz" . 2>/dev/null || true
    find "${MM_BASE}" -mindepth 1 -maxdepth 1 ! -name files -exec rm -rf {} + || true
}

# --- guest image ----------------------------------------------------------------

# build_guest is the guest build from run.sh, with the old image.
build_guest() {
    local build_dir build_start
    if [[ -n "${SPIKE_GUEST_DIR:-}" ]]; then
        log "using guest image from ${SPIKE_GUEST_DIR}"
        cp "${SPIKE_GUEST_DIR}/live.kernel" "${SPIKE_GUEST_DIR}/live.initrd" "${STAGE}/" || die "no guest image in ${SPIKE_GUEST_DIR}"
        return
    fi
    log "building guest image with the vmbetter in ${OLD_IMAGE}"
    build_dir="$(mktemp -d)"
    cp -r "${SCRIPT_DIR}/image/live.conf" "${SCRIPT_DIR}/image/overlay" "${build_dir}/"
    build_start=$(date +%s)
    docker run --rm --privileged -v "${build_dir}:/build" -w /build "${OLD_IMAGE}" bash -euxc '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends debootstrap ca-certificates wget cpio gzip xz-utils >/dev/null
        # Same keyring handling as tests/live/run.sh (Ubuntu 22.04 lacks the bookworm keys).
        K=debian-archive-keyring_2023.3+deb12u2_all.deb
        wget -q "https://deb.debian.org/debian/pool/main/d/debian-archive-keyring/$K"
        echo "f699e2f88dca05212f2a452b58475f2993cb6993dfbafb1d0205a3291eb8b4b8  $K" | sha256sum -c -
        dpkg-deb -x "$K" /keyring
        mkdir -p overlay/usr/bin
        cp /opt/minimega/bin/miniccc /opt/minimega/bin/minirouter /opt/minimega/bin/protonuke overlay/usr/bin/
        /opt/minimega/bin/vmbetter -branch bookworm -mirror https://deb.debian.org/debian -debootstrap-append=--keyring=/keyring/usr/share/keyrings/debian-archive-keyring.gpg -O live live.conf
    ' > "${ART}/logs/guest-build.log" 2>&1 \
        || { tail -50 "${ART}/logs/guest-build.log"; rm -rf "${build_dir}"; die "guest image build failed"; }
    mv "${build_dir}/live.kernel" "${build_dir}/live.initrd" "${STAGE}/" || die "vmbetter produced no live.kernel/live.initrd"
    rm -rf "${build_dir}"
    grep -E 'unpacked rootfs|bundled' "${ART}/logs/guest-build.log" || true
    log "guest image built in $(( $(date +%s) - build_start ))s"
}

# write_wrapper writes a QEMU wrapper that appends QEMU's stderr to QEMU_LOG:
# minimega keeps the stderr of a non-bare-metal VM only in memory.
write_wrapper() {
    cat > "${WRAP}" <<EOF
#!/bin/sh
echo "=== \$(date -u +%Y-%m-%dT%H:%M:%SZ) kvm \$*" >> "${QEMU_LOG}"
exec kvm "\$@" 2>> "${QEMU_LOG}"
EOF
    chmod 0755 "${WRAP}"
}

qemu_version() {
    docker run --rm "$1" kvm -version 2>&1 | head -n 1 || true
}

# --- guest operations -------------------------------------------------------

# configure_vm MACHINE STATE sets the fixed VM configuration in the namespace.
configure_vm() {
    local machine=$1 state=$2 c out
    local cmds=(
        "clear vm config"
        "vm config qemu ${WRAP}"
        "vm config kernel ${STAGE}/live.kernel"
        "vm config initrd ${STAGE}/live.initrd"
        "vm config append live.hostname=spike live.dhcp=0"
        "vm config memory ${MEMORY}"
        "vm config vcpus 1"
        "vm config uuid ${UUID}"
        "vm config backchannel true"
    )
    if [[ -n "${machine}" ]]; then cmds+=("vm config machine ${machine}"); fi
    if [[ -n "${state}" ]]; then cmds+=("vm config state ${state}"); fi
    for c in "${cmds[@]}"; do
        if ! out="$(ns_run "${c}")"; then
            DETAIL="'${c}' failed: $(oneline "${out}")"
            return 1
        fi
    done
}

wait_cc() {
    local limit=$1 start=${SECONDS} out
    while (( SECONDS - start < limit )); do
        out="$(MM_QUIET=1 mmv ".columns uuid cc clients" || true)"
        if grep -qixF "${UUID}" <<<"${out}"; then
            WAITED=$(( SECONDS - start ))
            return 0
        fi
        sleep 3
    done
    return 1
}

# cc_exec SCRIPT [LIMIT] runs "sh -c SCRIPT" on the guest and sets CC_STDOUT,
# CC_STDERR, and CC_EXIT from miniccc_responses. minimega expands $VAR in every
# argument (cliPreprocess), so SCRIPT must not contain $ or quoting characters.
cc_exec() {
    local script=$1 limit=${2:-60} prefix row id n start dirs
    CC_SEQ=$(( CC_SEQ + 1 ))
    prefix="spike${CC_SEQ}"
    CC_STDOUT=""
    CC_STDERR=""
    CC_EXIT=""
    if [[ "${script}" == *[\$\`\"\'*#\\]* ]]; then
        echo "  cc_exec: refusing a guest script with \$, a quote, *, # or \\: ${script}" >&2
        return 1
    fi
    ns_run "cc prefix ${prefix}" >/dev/null || return 1
    if ! ns_run "cc exec sh -c '${script}'" >/dev/null; then
        ns_run "clear cc prefix" >/dev/null || true
        return 1
    fi
    ns_run "clear cc prefix" >/dev/null || true
    start=${SECONDS}
    while :; do
        row="$(MM_QUIET=1 mmv ".columns id,responses .filter prefix=${prefix} cc commands" || true)"
        row="$(grep -E '^[0-9]+,[0-9]+$' <<<"${row}" | head -n 1 || true)"
        id="${row%%,*}"
        n="${row##*,}"
        if [[ "${id}" =~ ^[0-9]+$ && "${n}" =~ ^[0-9]+$ ]] && (( n >= 1 )); then
            break
        fi
        if (( SECONDS - start >= limit )); then
            echo "  cc ${prefix}: no response after ${limit}s (row '${row}')" >&2
            return 1
        fi
        sleep 2
    done
    sleep 1
    dirs=("${MM_FILES}/${NS}/miniccc_responses/${id}"/*)
    if [[ ! -d "${dirs[0]}" ]]; then
        echo "  cc ${prefix}: no response directory for command ${id}" >&2
        return 1
    fi
    CC_STDOUT="$(cat "${dirs[0]}/stdout" 2>/dev/null || true)"
    CC_STDERR="$(cat "${dirs[0]}/stderr" 2>/dev/null || true)"
    CC_EXIT="$(tr -d '[:space:]' < "${dirs[0]}/exitcode" 2>/dev/null || true)"
    printf 'cc %s (command %s) exit=%s stdout=%q stderr=%q\n' "${prefix}" "${id}" "${CC_EXIT:-none}" \
        "${CC_STDOUT}" "${CC_STDERR}" >> "${ART}/commands.log"
    echo "  cc ${prefix} -> exit ${CC_EXIT:-none}: $(oneline "${CC_STDOUT}")" >&2
}

# read_failed WHAT logs the raw guest output of the last cc_exec.
read_failed() {
    printf 'guest read failed (%s): exit=%s stdout=%q stderr=%q\n' "$1" "${CC_EXIT:-none}" \
        "${CC_STDOUT}" "${CC_STDERR}" | tee -a "${ART}/commands.log" >&2
}

# first_field prints the first field of the first line of $1.
first_field() { awk 'NR == 1 { print $1 }' <<<"$1"; }

# guest_uptime sets UPTIME (not in a subshell: cc_exec must keep CC_SEQ).
guest_uptime() {
    UPTIME=""
    if ! cc_exec 'cat /proc/uptime' 60; then
        read_failed "cat /proc/uptime"
        return 1
    fi
    UPTIME="$(first_field "${CC_STDOUT}")"
    if [[ ! "${UPTIME}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        read_failed "cat /proc/uptime"
        return 1
    fi
}

gt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a > b) }'; }

# launch_fresh MACHINE launches and starts a VM from the kernel and initrd.
launch_fresh() {
    local out
    configure_vm "$1" "" || return 1
    if ! out="$(ns_run "vm launch kvm ${VM}")"; then
        DETAIL="vm launch failed: $(oneline "${out}")"
        return 1
    fi
    if ! out="$(ns_run "vm start ${VM}")"; then
        DETAIL="vm start failed: $(oneline "${out}")"
        return 1
    fi
}

wait_boot() {
    if ! wait_cc 180; then
        DETAIL="miniccc did not connect within 180s (vm state $(vm_state))"
        return 1
    fi
    log "miniccc of ${VM} connected (waited ${WAITED}s)"
}

boot_fresh() { launch_fresh "" && wait_boot; }

# state_machine FILE prints the machine name in the configuration section that
# follows the QEVM magic and version 3: 0x07, a big-endian 32-bit length, the name.
state_machine() {
    local f=$1 hex len name
    hex="$(head -c 13 "${f}" | od -An -v -tx1 | tr -d ' \n')"
    [[ "${hex:0:18}" == 5145564d0000000307 ]] || return 1
    len=$(( 16#${hex:18:8} ))
    (( len > 0 && len < 256 )) || return 1
    name="$(dd if="${f}" bs=1 skip=13 count="${len}" 2>/dev/null)"
    [[ "${#name}" -eq "${len}" && "${name}" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
    printf '%s' "${name}"
}

be32() {
    local n=$1 s
    for s in 24 16 8 0; do
        printf '%b' "\\0$(printf '%03o' $(( (n >> s) & 255 )))"
    done
}

# rewrite_state SRC DST MACHINE writes a copy of SRC whose header names MACHINE.
# The bytes after the old name are streamed unchanged.
rewrite_state() {
    local src=$1 dst=$2 new=$3 old want got
    if ! old="$(state_machine "${src}")"; then
        DETAIL="no QEVM configuration header in ${src}"
        return 1
    fi
    log "rewriting the header of ${src}: ${old} -> ${new}"
    if ! { head -c 9 "${src}" && be32 "${#new}" && printf '%s' "${new}" \
        && tail -c +$(( 14 + ${#old} )) "${src}"; } > "${dst}"; then
        DETAIL="could not write ${dst}"
        return 1
    fi
    echo "  original header:"
    od -A d -v -t x1z -N 48 "${src}" | sed 's/^/    /'
    echo "  rewritten header:"
    od -A d -v -t x1z -N 48 "${dst}" | sed 's/^/    /'
    want=$(( $(stat -c %s "${src}") - ${#old} + ${#new} ))
    got="$(stat -c %s "${dst}")"
    if (( got != want )); then
        DETAIL="rewritten file has ${got} bytes, expected ${want}"
        return 1
    fi
    if [[ "$(state_machine "${dst}" || true)" != "${new}" ]]; then
        DETAIL="rewritten header does not parse as ${new}"
        return 1
    fi
    if ! cmp -s <(tail -c +$(( 14 + ${#old} )) "${src}") <(tail -c +$(( 14 + ${#new} )) "${dst}"); then
        DETAIL="the stream after the header differs from the original"
        return 1
    fi
    log "rewritten ${dst}: ${got} bytes, header ${new}, rest of the stream identical"
}

# save_guest NAME writes a marker, records uptime and machine type, and runs vm save NAME.
save_guest() {
    local name=$1 file="${MM_FILES}/$1.state" start status seen="" size=0
    HEADER=unknown
    MARKER="spike-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    if ! cc_exec "echo ${MARKER} > /tmp/spike-marker && cat /tmp/spike-marker" 60 \
        || [[ "${CC_EXIT}" != "0" || "$(oneline "${CC_STDOUT}")" != "${MARKER}" ]]; then
        read_failed "write marker"
        DETAIL="could not write the marker (exit ${CC_EXIT:-none}, stdout '$(oneline "${CC_STDOUT}")')"
        return 1
    fi
    log "marker ${MARKER} written to /tmp/spike-marker"
    if ! guest_uptime; then
        DETAIL="could not read /proc/uptime"
        return 1
    fi
    if ! gt "${UPTIME}" "${MIN_UPTIME}"; then
        log "guest uptime ${UPTIME}s; waiting until it is over ${MIN_UPTIME}s"
        sleep "$(awk -v a="${MIN_UPTIME}" -v b="${UPTIME}" 'BEGIN { printf "%d", a - b + 2 }')"
        if ! guest_uptime; then
            DETAIL="could not read /proc/uptime"
            return 1
        fi
    fi
    SAVED_UPTIME="${UPTIME}"
    log "guest uptime before save: ${SAVED_UPTIME}s"
    MACHINE="$(qmp_machine)"
    log "machine type (qom-get /machine type): ${MACHINE:-unknown}"

    if ! status="$(ns_run "vm save ${VM} ${name}")"; then
        DETAIL="vm save failed: $(oneline "${status}")"
        return 1
    fi
    start=${SECONDS}
    while :; do
        status="$(MM_QUIET=1 mmv ".columns status .filter name=${VM} vm save" || true)"
        status="$(grep -E '^[a-z-]+$' <<<"${status}" | head -n 1 || true)"
        if [[ -n "${status}" && " ${seen} " != *" ${status} "* ]]; then
            log "vm save status: ${status}"
            seen+=" ${status}"
        fi
        case "${status}" in
        completed) break ;;
        failed)
            DETAIL="vm save status failed"
            return 1
            ;;
        esac
        if (( SECONDS - start >= 120 )); then
            DETAIL="vm save not completed after 120s (statuses:${seen:- none})"
            return 1
        fi
        sleep 2
    done
    for _ in $(seq 1 15); do
        size="$(stat -c %s "${file}" 2>/dev/null || echo 0)"
        if (( size > 0 )); then break; fi
        sleep 2
    done
    if (( size == 0 )); then
        DETAIL="vm save completed but ${file} is missing or empty"
        return 1
    fi
    HEADER="$(state_machine "${file}" || echo unparsed)"
    log "state file ${file}: ${size} bytes, machine in stream header: ${HEADER}"
    od -A d -v -t x1z -N 48 "${file}" | sed 's/^/    /' || true
    ls -l "${MM_FILES}"
}

# restore_guest STATE MACHINE MARKER UPTIME launches a VM from STATE and checks
# that it runs, that miniccc reconnects, and that the marker and uptime survived.
restore_guest() {
    local state=$1 machine=$2 want_marker=$3 want_uptime=$4 out t0 st qs t_run got_marker got_uptime now_machine
    configure_vm "${machine}" "${state}" || return 1
    t0=${SECONDS}
    if ! out="$(ns_run "vm launch kvm ${VM}")"; then
        DETAIL="vm launch failed: $(oneline "${out}")"
        return 1
    fi
    # wait until QEMU has read the stream (status leaves inmigrate) or exits
    while :; do
        st="$(vm_state)"
        if [[ "${st}" == ERROR || "${st}" == QUIT ]]; then
            DETAIL="QEMU exited while it loaded the state (vm state ${st})"
            return 1
        fi
        qs="$(qmp_status)"
        if [[ -n "${qs}" && "${qs}" != inmigrate ]]; then
            log "incoming migration done after $(( SECONDS - t0 ))s: qmp status ${qs}, vm state ${st}"
            break
        fi
        if (( SECONDS - t0 >= 120 )); then
            DETAIL="still loading after 120s (qmp status ${qs:-none}, vm state ${st})"
            return 1
        fi
        sleep 2
    done
    if ! out="$(ns_run "vm start ${VM}")"; then
        DETAIL="vm start failed: $(oneline "${out}")"
        return 1
    fi
    while :; do
        st="$(vm_state)"
        qs="$(qmp_status)"
        if [[ "${st}" == ERROR || "${st}" == QUIT ]]; then
            DETAIL="QEMU exited after vm start (vm state ${st})"
            return 1
        fi
        if [[ "${st}" == RUNNING && "${qs}" == running ]]; then break; fi
        if (( SECONDS - t0 >= 180 )); then
            DETAIL="not running after vm start (qmp status ${qs:-none}, vm state ${st})"
            return 1
        fi
        sleep 2
    done
    t_run=$(( SECONDS - t0 ))
    log "VM RUNNING (qmp status running) ${t_run}s after launch"
    if ! wait_cc 90; then
        DETAIL="VM running (qmp running) but miniccc did not reconnect within 90s"
        return 1
    fi
    log "miniccc reconnected after ${WAITED}s"
    if ! guest_uptime; then
        DETAIL="miniccc reconnected but cat /proc/uptime failed (stdout '$(oneline "${CC_STDOUT}")')"
        return 1
    fi
    got_uptime="${UPTIME}"
    if ! cc_exec 'cat /tmp/spike-marker' 60; then
        read_failed "cat /tmp/spike-marker"
        DETAIL="miniccc reconnected but did not answer cat /tmp/spike-marker (guest uptime ${got_uptime}s)"
        return 1
    fi
    got_marker="$(first_field "${CC_STDOUT}")"
    if [[ "${CC_EXIT}" != "0" ]]; then read_failed "cat /tmp/spike-marker"; fi
    now_machine="$(qmp_machine)"
    if [[ "${got_marker}" != "${want_marker}" ]]; then
        DETAIL="marker is '${got_marker}', expected '${want_marker}' (guest uptime ${got_uptime}s: fresh boot?)"
        return 1
    fi
    if ! gt "${got_uptime}" "${want_uptime}"; then
        DETAIL="marker matches but guest uptime ${got_uptime}s is not over the saved ${want_uptime}s"
        return 1
    fi
    DETAIL="running ${t_run}s after launch, cc after ${WAITED}s more, marker matches, uptime ${got_uptime}s > saved ${want_uptime}s, machine ${now_machine:-unknown}"
}

kill_flush() {
    local start=${SECONDS} st
    ns_run "vm kill ${VM}" >/dev/null 2>&1 || true
    while (( SECONDS - start < 30 )); do
        st="$(vm_state)"
        if [[ -z "${st}" || "${st}" == QUIT || "${st}" == ERROR ]]; then break; fi
        sleep 2
    done
    ns_run "vm flush" >/dev/null 2>&1 || true
}

# qemu_error prints the last QEMU stderr lines with the "load of migration
# failed" line at the end, else the VM error tag.
qemu_error() {
    local lines load other tags
    lines="$(grep -v '^=== ' "${QEMU_LOG}" 2>/dev/null | sed '/^[[:space:]]*$/d' || true)"
    if [[ -n "${lines}" ]]; then
        load="$(grep -m 1 'load of migration failed' <<<"${lines}" || true)"
        other="$(grep -v 'load of migration failed' <<<"${lines}" | tail -n 4 || true)"
        oneline "qemu stderr: ${other}${other:+ }${load}" 1000
        return
    fi
    tags="$(MM_QUIET=1 mmv ".columns tags .filter name=${VM} vm info" 2>/dev/null || true)"
    if [[ -n "${tags}" ]]; then oneline "vm tags: ${tags}" 1000; fi
}

# collect_evidence LABEL [CONTAINER LABEL] saves vm info, QEMU stderr, and
# minimega log lines.
collect_evidence() {
    local label=$1 f="${ART}/evidence-$1.txt" log_label=${2:-$1}
    {
        echo "## vm info (${NS})"
        MM_QUIET=1 ns_run ".columns name,state,tags vm info" || true
        echo "## QEMU stderr and command lines (${QEMU_LOG})"
        cat "${QEMU_LOG}" 2>/dev/null || true
        echo "## minimega log: errors, qemu, migration"
        grep -iE 'error|qemu|migrat|incoming|state' "${ART}/logs/minimega-${log_label}.log" 2>/dev/null | tail -n 80 || true
    } > "${f}" 2>&1
    sed 's/^/    | /' "${f}"
    cp "${QEMU_LOG}" "${ART}/logs/qemu-stderr-${label}.log" 2>/dev/null || true
}

# --- phases -------------------------------------------------------------------

# run_save_old boots both old VMs at once, so that the SAVE-OLD-PC guest has
# its uptime already when SAVE-OLD is done, and then saves the default one.
run_save_old() {
    : > "${QEMU_LOG}"
    if ! start_mm "${OLD_IMAGE}" save-old; then
        DETAIL="minimega did not start from ${OLD_IMAGE}"
        return 1
    fi
    use_vm saveold "${VM_MAIN}" "${UUID_MAIN}"
    launch_fresh "" || return 1
    use_vm saveoldpc "${VM_PC}" "${UUID_PC}"
    if launch_fresh "${OLD_PC_MACHINE}"; then
        PC_LAUNCHED=1
    else
        PC_LAUNCH_ERR="${DETAIL}"
    fi
    use_vm saveold "${VM_MAIN}" "${UUID_MAIN}"
    wait_boot || return 1
    save_guest spike-old || return 1
    MACHINE_OLD="${MACHINE:-unknown}"
    OLD_HEADER="${HEADER}"
    DETAIL="saved ${STATE_OLD}, header ${HEADER}, marker ${MARKER}, uptime ${SAVED_UPTIME}s"
}

# run_save_old_pc saves the second old VM, in the SAVE-OLD container.
run_save_old_pc() {
    use_vm saveoldpc "${VM_PC}" "${UUID_PC}"
    if [[ "${PC_LAUNCHED}" != "1" ]]; then
        DETAIL="VM not launched: ${PC_LAUNCH_ERR:-SAVE-OLD stopped before the launch}"
        return 1
    fi
    wait_boot || return 1
    save_guest spike-old-pc || return 1
    MACHINE_OLD_PC="${MACHINE:-unknown}"
    PC_HEADER="${HEADER}"
    DETAIL="saved ${STATE_OLD_PC}, header ${HEADER}, marker ${MARKER}, uptime ${SAVED_UPTIME}s"
}

# run_restore LABEL MACHINE STATE MARKER UPTIME restores STATE on the new image
# for the VM that use_vm selected.
run_restore() {
    local label=$1 machine=$2 state=$3 marker=$4 uptime=$5 rc=0 err
    : > "${QEMU_LOG}"
    if ! start_mm "${NEW_IMAGE}" "${label}"; then
        DETAIL="minimega did not start from ${NEW_IMAGE}"
        rc=1
    elif ! restore_guest "${state}" "${machine}" "${marker}" "${uptime}"; then
        rc=1
        sleep 2
        err="$(qemu_error)"
        if [[ -n "${err}" ]]; then DETAIL="${DETAIL}; ${err}"; fi
    fi
    collect_evidence "${label}"
    kill_flush
    stop_mm "${label}"
    return "${rc}"
}

run_control() {
    local rc=0 err ctl_marker ctl_uptime
    use_vm ctlsave "${VM_MAIN}" "${UUID_MAIN}"
    : > "${QEMU_LOG}"
    if ! start_mm "${NEW_IMAGE}" control-new; then
        DETAIL="minimega did not start from ${NEW_IMAGE}"
        return 1
    fi
    if boot_fresh && save_guest spike-ctl; then
        ctl_marker="${MARKER}"
        ctl_uptime="${SAVED_UPTIME}"
        log "control: saved on the new image with machine ${MACHINE:-unknown}"
        kill_flush
        cp "${QEMU_LOG}" "${ART}/logs/qemu-stderr-control-save.log" 2>/dev/null || true
        : > "${QEMU_LOG}"
        use_vm ctlrestore "${VM_MAIN}" "${UUID_MAIN}"
        if ! restore_guest "${STATE_CTL}" "" "${ctl_marker}" "${ctl_uptime}"; then
            rc=1
            sleep 2
            err="$(qemu_error)"
            if [[ -n "${err}" ]]; then DETAIL="${DETAIL}; ${err}"; fi
        fi
    else
        rc=1
        DETAIL="save on the new image failed: ${DETAIL}"
    fi
    collect_evidence control-new
    kill_flush
    stop_mm control-new
    return "${rc}"
}

# --- results and cleanup ------------------------------------------------------

print_results() {
    local block
    if [[ "${RESULTS_PRINTED}" == "1" ]]; then return; fi
    RESULTS_PRINTED=1
    block="RESULT qemu_old=${QEMU_OLD} qemu_new=${QEMU_NEW}
RESULT machine_old=${MACHINE_OLD} header=${OLD_HEADER}
RESULT machine_old_pc=${MACHINE_OLD_PC} header=${PC_HEADER}
RESULT restore_unpinned=${RES_UNPINNED} detail=\"$(oneline "${DET_UNPINNED}" 1400)\"
RESULT restore_pinned=${RES_PINNED} detail=\"$(oneline "${DET_PINNED}" 1400)\"
RESULT restore_rewritten=${RES_RW} detail=\"$(oneline "${DET_RW}" 1400)\"
RESULT restore_pc_pinned=${RES_PC} detail=\"$(oneline "${DET_PC}" 1400)\"
RESULT control_new=${RES_CONTROL} detail=\"$(oneline "${DET_CONTROL}" 1400)\""
    echo
    printf '%s\n' "${block}" | tee "${ART}/results.txt"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        # shellcheck disable=SC2016
        printf '### Spike: restore QEMU 6.2 state on QEMU 11.1.3\n\n```text\n%s\n```\n' "${block}" >> "${GITHUB_STEP_SUMMARY}" || true
    fi
}

# shellcheck disable=SC2329 # called by the EXIT trap
cleanup() {
    local rc=$?
    set +e
    if [[ "${OWN_CONTAINER}" == "1" ]]; then
        docker logs "${CONTAINER}" > "${ART}/logs/container-at-exit.log" 2>&1
        docker rm -f "${CONTAINER}" >/dev/null 2>&1
    fi
    for f in "${STATE_OLD}" "${STATE_OLD_PC}" "${STATE_RW}" "${STATE_CTL}"; do
        if [[ -f "${f}" ]]; then head -c 1048576 "${f}" > "${ART}/$(basename "${f}").head"; fi
    done
    print_results
    if [[ "${OWN_BASE}" == "1" && "${SPIKE_KEEP:-0}" != "1" ]]; then rm -rf "${MM_BASE}"; fi
    exit "${rc}"
}

# --- main -------------------------------------------------------------------------

[[ -n "${OLD_IMAGE}" && -n "${NEW_IMAGE}" ]] || die "usage: $0 <old image> <new image> [artifacts dir]"
mkdir -p "${ART_DIR}/logs"
ART="$(cd "${ART_DIR}" && pwd)"
exec > >(tee -a "${ART}/spike.log") 2>&1
trap cleanup EXIT

[[ "$(id -u)" == "0" ]] || die "run as root (the minimega socket and KVM need it)"
command -v docker >/dev/null || die "docker not found"
[[ -c /dev/kvm ]] || die "/dev/kvm not found; KVM is required"

if docker inspect "${CONTAINER}" >/dev/null 2>&1; then
    [[ "${SPIKE_FORCE:-0}" == "1" ]] || die "container ${CONTAINER} exists; set SPIKE_FORCE=1 to replace it"
    docker rm -f "${CONTAINER}" >/dev/null
fi
if [[ -e "${MM_BASE}" ]]; then
    [[ "${SPIKE_FORCE:-0}" == "1" ]] || die "${MM_BASE} exists; set SPIKE_FORCE=1 to delete it"
fi
rm -rf "${MM_BASE}"
mkdir -p "${STAGE}"
OWN_BASE=1

modprobe openvswitch 2>/dev/null || true
lsmod | grep -q '^openvswitch' || log "warning: openvswitch module not loaded; Open vSwitch may fail to start"

phase "IMAGES"
for image in "${OLD_IMAGE}" "${NEW_IMAGE}"; do
    if [[ "${SPIKE_PULL:-1}" == "1" ]]; then
        log "pulling ${image}"
        docker pull -q "${image}" || die "unable to pull ${image}"
    fi
    docker image inspect "${image}" --format "${image} {{.Id}} created {{.Created}}" >> "${ART}/images.txt" \
        || die "image ${image} not found"
    tail -n 1 "${ART}/images.txt"
done
old_line="$(qemu_version "${OLD_IMAGE}")"
new_line="$(qemu_version "${NEW_IMAGE}")"
log "old kvm -version: ${old_line}"
log "new kvm -version: ${new_line}"
QEMU_OLD="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' <<<"${old_line}" | head -n 1 || true)"
QEMU_NEW="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' <<<"${new_line}" | head -n 1 || true)"
[[ "${QEMU_OLD}" == 6.2.* ]] || die "old image ${OLD_IMAGE} runs QEMU '${QEMU_OLD:-unknown}', expected 6.2.x"
[[ "${QEMU_NEW}" == 11.1.3 ]] || die "new image ${NEW_IMAGE} runs QEMU '${QEMU_NEW:-unknown}', expected 11.1.3"

phase "GUEST"
build_guest
write_wrapper
ls -l "${STAGE}"

# SAVE-OLD: boot on QEMU 6.2 with the default machine, write a marker, vm save.
phase "SAVE-OLD"
save_ok=0
if run_save_old; then
    save_ok=1
    OLD_MARKER="${MARKER}"
    OLD_UPTIME="${SAVED_UPTIME}"
    log "SAVE-OLD ok: ${DETAIL}"
else
    log "SAVE-OLD FAILED: ${DETAIL}"
    DET_UNPINNED="not run: SAVE-OLD failed: ${DETAIL}"
    DET_PINNED="${DET_UNPINNED}"
    DET_RW="${DET_UNPINNED}"
fi
collect_evidence save-old

# SAVE-OLD-PC: the second old VM (vm config machine pc), in the same container.
phase "SAVE-OLD-PC"
pc_save_ok=0
if run_save_old_pc; then
    pc_save_ok=1
    PC_MARKER="${MARKER}"
    PC_UPTIME="${SAVED_UPTIME}"
    log "SAVE-OLD-PC ok: ${DETAIL}"
else
    log "SAVE-OLD-PC FAILED: ${DETAIL}"
    DET_PC="not run: SAVE-OLD-PC failed: ${DETAIL}"
fi
collect_evidence save-old-pc save-old
stop_mm save-old

if [[ "${save_ok}" == "1" ]]; then
    # RESTORE-NEW-UNPINNED: the same VM on QEMU 11.1.3, default machine (expected to fail).
    phase "RESTORE-NEW-UNPINNED"
    use_vm unpinned "${VM_MAIN}" "${UUID_MAIN}"
    if run_restore restore-new-unpinned "" "${STATE_OLD}" "${OLD_MARKER}" "${OLD_UPTIME}"; then RES_UNPINNED=pass; fi
    DET_UNPINNED="header ${OLD_HEADER}; ${DETAIL}"
    log "RESTORE-NEW-UNPINNED ${RES_UNPINNED}: ${DET_UNPINNED}"

    # RESTORE-NEW-PINNED: the same VM on QEMU 11.1.3 with machine pc-i440fx-6.2.
    phase "RESTORE-NEW-PINNED"
    use_vm pinned "${VM_MAIN}" "${UUID_MAIN}"
    if run_restore restore-new-pinned "${PINNED_MACHINE}" "${STATE_OLD}" "${OLD_MARKER}" "${OLD_UPTIME}"; then RES_PINNED=pass; fi
    DET_PINNED="header ${OLD_HEADER}; ${DETAIL}"
    log "RESTORE-NEW-PINNED ${RES_PINNED}: ${DET_PINNED}"

    # RESTORE-NEW-REWRITTEN: the SAVE-OLD state with pc-i440fx-6.2 in its header, pinned to it.
    phase "RESTORE-NEW-REWRITTEN"
    if rewrite_state "${STATE_OLD}" "${STATE_RW}" "${PINNED_MACHINE}"; then
        use_vm rewritten "${VM_MAIN}" "${UUID_MAIN}"
        if run_restore restore-new-rewritten "${PINNED_MACHINE}" "${STATE_RW}" "${OLD_MARKER}" "${OLD_UPTIME}"; then RES_RW=pass; fi
        DET_RW="header ${OLD_HEADER} rewritten to ${PINNED_MACHINE}; ${DETAIL}"
    else
        DET_RW="not run: header rewrite failed: ${DETAIL}"
    fi
    log "RESTORE-NEW-REWRITTEN ${RES_RW}: ${DET_RW}"
fi

if [[ "${pc_save_ok}" == "1" ]]; then
    # RESTORE-NEW-PC-PINNED: the SAVE-OLD-PC state on QEMU 11.1.3 with machine pc-i440fx-6.2.
    phase "RESTORE-NEW-PC-PINNED"
    use_vm pcpinned "${VM_PC}" "${UUID_PC}"
    if run_restore restore-new-pc-pinned "${PINNED_MACHINE}" "${STATE_OLD_PC}" "${PC_MARKER}" "${PC_UPTIME}"; then RES_PC=pass; fi
    DET_PC="header ${PC_HEADER}; ${DETAIL}"
    log "RESTORE-NEW-PC-PINNED ${RES_PC}: ${DET_PC}"
fi

# CONTROL-NEW: save and restore on QEMU 11.1.3 only, to prove the procedure.
phase "CONTROL-NEW"
if run_control; then RES_CONTROL=pass; fi
DET_CONTROL="${DETAIL}"
log "CONTROL-NEW ${RES_CONTROL}: ${DET_CONTROL}"

status=0
if [[ "${save_ok}" != "1" ]]; then
    log "the procedure could not run: SAVE-OLD failed"
    status=1
elif [[ "${RES_CONTROL}" != "pass" && "${RES_PINNED}" != "pass" ]]; then
    log "CONTROL-NEW failed too, so the RESTORE-NEW-PINNED failure is not conclusive"
    status=1
elif [[ "${RES_CONTROL}" != "pass" ]]; then
    log "warning: CONTROL-NEW failed, but RESTORE-NEW-PINNED passed on its own"
fi
print_results
exit "${status}"
