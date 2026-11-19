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
#   RESTORE-NEW-UNPINNED    restore that state on the new image, default machine
#   RESTORE-NEW-PINNED      the same, with vm config machine pc-i440fx-6.2
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
STATE_CTL="${MM_FILES}/spike-ctl.state"
PINNED_MACHINE=pc-i440fx-6.2

VM=spike
UUID=5b1d0000-0000-4000-8000-00000000a5e1
MEMORY=512
MIN_UPTIME="${SPIKE_MIN_UPTIME:-120}"

QMP_TYPE='{ "execute": "qom-get", "arguments": { "path": "/machine", "property": "type" } }'
QMP_STATUS='{ "execute": "query-status" }'

QEMU_OLD=unknown
QEMU_NEW=unknown
MACHINE_OLD=unknown
RES_UNPINNED=fail
DET_UNPINNED="not run"
RES_PINNED=fail
DET_PINNED="not run"
RES_CONTROL=fail
DET_CONTROL="not run"
RESULTS_PRINTED=0
OWN_BASE=0
OWN_CONTAINER=0

NS=""
DETAIL=""
CC_SEQ=0
CC_STDOUT=""
CC_EXIT=""
WAITED=0
MARKER=""
UPTIME=""
SAVED_UPTIME=""
OLD_MARKER=""
OLD_UPTIME=""
MACHINE=""

log() { echo "==> [$(date +%H:%M:%S)] $*"; }
phase() { echo; echo "==================== $* ===================="; }
die() { echo "ERROR: $*" >&2; exit 1; }

# oneline joins text into one grep-friendly line without double quotes.
oneline() { printf '%s' "$1" | tr '\n\r\t"' "   '" | tr -s ' ' | sed 's/^ //; s/ $//' | cut -c1-400; }

# --- minimega commands ------------------------------------------------------

mm() { timeout "${MM_TIMEOUT:-120}" docker exec "${CONTAINER}" minimega -e "$1"; }

# mmrun runs one minimega command line, prints its stdout and stderr, logs both,
# and fails when minimega reports an error. MM_QUIET=1 keeps it out of the console.
mmrun() {
    local out errf err rc=0
    errf="$(mktemp)"
    out="$(mm "$1" 2>"${errf}")" || rc=$?
    err="$(cat "${errf}")"
    rm -f "${errf}"
    if [[ -n "${err}" ]]; then
        rc=1
    fi
    {
        echo "mm[${NS}]> $1"
        if [[ -n "${out}" ]]; then printf '%s\n' "${out}"; fi
        if [[ -n "${err}" ]]; then printf 'stderr: %s\n' "${err}"; fi
    } >> "${ART}/commands.log"
    if [[ "${MM_QUIET:-0}" != "1" ]]; then
        echo "  mm> $1" >&2
        if [[ -n "${out}${err}" ]]; then printf '%s\n' "${out}" "${err}" | sed '/^$/d; s/^/      /' >&2; fi
    fi
    if [[ -n "${out}" ]]; then printf '%s\n' "${out}"; fi
    if [[ -n "${err}" ]]; then printf '%s\n' "${err}"; fi
    return "${rc}"
}

# mmv runs a command in the phase namespace with bare CSV output.
mmv() { mmrun "namespace ${NS} .csv true .headers false .annotate false $1"; }

ns_run() { mmrun "namespace ${NS} $1"; }

vm_state() { oneline "$(MM_QUIET=1 mmv ".columns state .filter name=${VM} vm info" || true)"; }

qmp() { mmrun "namespace ${NS} .annotate false vm qmp ${VM} '$1'"; }

qmp_status() {
    local out
    out="$(MM_QUIET=1 qmp "${QMP_STATUS}" || true)"
    sed -n 's/.*"status": *"\([a-z-]*\)".*/\1/p' <<<"${out}" | head -n 1
}

qmp_machine() {
    local out
    out="$(qmp "${QMP_TYPE}" || true)"
    sed -n 's/.*"return": *"\([^"]*\)".*/\1/p' <<<"${out}" | head -n 1
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
        if grep -qiF "${UUID}" <<<"${out}"; then
            WAITED=$(( SECONDS - start ))
            return 0
        fi
        sleep 3
    done
    return 1
}

# cc_exec SCRIPT [LIMIT] runs "sh -c SCRIPT" on the guest (no single quotes in
# SCRIPT) and sets CC_STDOUT and CC_EXIT from miniccc_responses.
cc_exec() {
    local script=$1 limit=${2:-60} prefix row id n start dirs
    CC_SEQ=$(( CC_SEQ + 1 ))
    prefix="spike${CC_SEQ}"
    CC_STDOUT=""
    CC_EXIT=""
    ns_run "cc prefix ${prefix}" >/dev/null || return 1
    if ! ns_run "cc exec sh -c '${script}'" >/dev/null; then
        ns_run "clear cc prefix" >/dev/null || true
        return 1
    fi
    ns_run "clear cc prefix" >/dev/null || true
    start=${SECONDS}
    while :; do
        row="$(MM_QUIET=1 mmv ".columns id,responses .filter prefix=${prefix} cc commands" || true)"
        row="$(head -n 1 <<<"${row}")"
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
    CC_EXIT="$(tr -d '[:space:]' < "${dirs[0]}/exitcode" 2>/dev/null || true)"
    echo "  cc ${prefix} -> exit ${CC_EXIT:-none}: $(oneline "${CC_STDOUT}")" >&2
}

# guest_uptime sets UPTIME (not in a subshell: cc_exec must keep CC_SEQ).
guest_uptime() {
    # shellcheck disable=SC2016
    cc_exec 'read u r < /proc/uptime && echo $u' 60 || return 1
    UPTIME="$(oneline "${CC_STDOUT}")"
    [[ "${UPTIME}" =~ ^[0-9]+(\.[0-9]+)?$ ]]
}

gt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a > b) }'; }

# boot_fresh launches and starts a VM from the kernel and initrd and waits for miniccc.
boot_fresh() {
    local out
    configure_vm "" "" || return 1
    if ! out="$(ns_run "vm launch kvm ${VM}")"; then
        DETAIL="vm launch failed: $(oneline "${out}")"
        return 1
    fi
    if ! out="$(ns_run "vm start ${VM}")"; then
        DETAIL="vm start failed: $(oneline "${out}")"
        return 1
    fi
    if ! wait_cc 180; then
        DETAIL="miniccc did not connect within 180s (vm state $(vm_state))"
        return 1
    fi
    log "miniccc connected after ${WAITED}s"
}

# save_guest NAME writes a marker, records uptime and machine type, and runs vm save NAME.
save_guest() {
    local name=$1 file="${MM_FILES}/$1.state" start status seen="" size=0 header
    MARKER="spike-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    if ! cc_exec "echo ${MARKER} > /tmp/spike-marker && cat /tmp/spike-marker" 60 \
        || [[ "${CC_EXIT}" != "0" || "$(oneline "${CC_STDOUT}")" != "${MARKER}" ]]; then
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
        status="$(oneline "$(MM_QUIET=1 mmv ".columns status .filter name=${VM} vm save" || true)")"
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
    header="$(head -c 65536 "${file}" | grep -aoE 'pc-(i440fx|q35)-[0-9]+\.[0-9]+' | head -n 1 || true)"
    log "state file ${file}: ${size} bytes, machine in stream header: ${header:-not found}"
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
    # shellcheck disable=SC2016
    if ! cc_exec 'cat /tmp/spike-marker 2>/dev/null || echo NO-MARKER; read u r < /proc/uptime && echo $u' 60; then
        DETAIL="miniccc reconnected but did not answer cc exec"
        return 1
    fi
    got_marker="$(oneline "$(head -n 1 <<<"${CC_STDOUT}")")"
    got_uptime="$(oneline "$(tail -n 1 <<<"${CC_STDOUT}")")"
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

# qemu_error prints the first QEMU stderr lines, else the VM error tag.
qemu_error() {
    local lines tags
    lines="$(grep -v '^=== ' "${QEMU_LOG}" 2>/dev/null | sed '/^[[:space:]]*$/d' | head -n 5 || true)"
    if [[ -n "${lines}" ]]; then
        oneline "qemu stderr: ${lines}"
        return
    fi
    tags="$(MM_QUIET=1 mmv ".columns tags .filter name=${VM} vm info" 2>/dev/null || true)"
    if [[ -n "${tags}" ]]; then oneline "vm tags: ${tags}"; fi
}

# collect_evidence LABEL saves vm info, QEMU stderr, and minimega log lines.
collect_evidence() {
    local label=$1 f="${ART}/evidence-$1.txt"
    {
        echo "## vm info (${NS})"
        MM_QUIET=1 ns_run ".columns name,state,tags vm info" || true
        echo "## QEMU stderr and command lines (${QEMU_LOG})"
        cat "${QEMU_LOG}" 2>/dev/null || true
        echo "## minimega log: errors, qemu, migration"
        grep -iE 'error|qemu|migrat|incoming|state' "${ART}/logs/minimega-${label}.log" 2>/dev/null | tail -n 80 || true
    } > "${f}" 2>&1
    sed 's/^/    | /' "${f}"
    cp "${QEMU_LOG}" "${ART}/logs/qemu-stderr-${label}.log" 2>/dev/null || true
}

# --- phases -------------------------------------------------------------------

run_save_old() {
    NS=saveold
    : > "${QEMU_LOG}"
    if ! start_mm "${OLD_IMAGE}" save-old; then
        DETAIL="minimega did not start from ${OLD_IMAGE}"
        return 1
    fi
    boot_fresh || return 1
    save_guest spike-old || return 1
    MACHINE_OLD="${MACHINE:-unknown}"
    DETAIL="saved ${STATE_OLD}, marker ${MARKER}, uptime ${SAVED_UPTIME}s"
}

# run_restore LABEL NAMESPACE MACHINE restores STATE_OLD on the new image.
run_restore() {
    local label=$1 machine=$3 rc=0 err
    NS=$2
    : > "${QEMU_LOG}"
    if ! start_mm "${NEW_IMAGE}" "${label}"; then
        DETAIL="minimega did not start from ${NEW_IMAGE}"
        rc=1
    elif ! restore_guest "${STATE_OLD}" "${machine}" "${OLD_MARKER}" "${OLD_UPTIME}"; then
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
    NS=ctlsave
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
        NS=ctlrestore
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
RESULT machine_old=${MACHINE_OLD}
RESULT restore_unpinned=${RES_UNPINNED} detail=\"$(oneline "${DET_UNPINNED}")\"
RESULT restore_pinned=${RES_PINNED} detail=\"$(oneline "${DET_PINNED}")\"
RESULT control_new=${RES_CONTROL} detail=\"$(oneline "${DET_CONTROL}")\""
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
    for f in "${STATE_OLD}" "${STATE_CTL}"; do
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
fi
collect_evidence save-old
stop_mm save-old

if [[ "${save_ok}" == "1" ]]; then
    # RESTORE-NEW-UNPINNED: the same VM on QEMU 11.1.3, default machine (expected to fail).
    phase "RESTORE-NEW-UNPINNED"
    if run_restore restore-new-unpinned unpinned ""; then RES_UNPINNED=pass; fi
    DET_UNPINNED="${DETAIL}"
    log "RESTORE-NEW-UNPINNED ${RES_UNPINNED}: ${DET_UNPINNED}"

    # RESTORE-NEW-PINNED: the same VM on QEMU 11.1.3 with machine pc-i440fx-6.2.
    phase "RESTORE-NEW-PINNED"
    if run_restore restore-new-pinned pinned "${PINNED_MACHINE}"; then RES_PINNED=pass; fi
    DET_PINNED="${DETAIL}"
    log "RESTORE-NEW-PINNED ${RES_PINNED}: ${DET_PINNED}"
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
