#!/bin/sh
# Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
# rights in this software.
#
# Check the QEMU installation of the minimega image. The Docker build runs this
# script, so no check needs KVM.
#
#   check-qemu.sh <upstream|distro> <expected version>
#
# Both modes check that kvm, qemu-img, and qemu-nbd run and print a version.
# The upstream mode (QEMU built by docker/qemu/Dockerfile) also checks the exact
# version, the system emulators, the QXL, SPICE, and VNC support, and that all
# shared libraries resolve.

set -u

usage() { echo "usage: $0 <upstream|distro> <expected version>" >&2; exit 2; }

[ $# -eq 2 ] || usage
MODE="$1"
EXPECTED="$2"
case "${MODE}" in
upstream | distro) ;;
*) usage ;;
esac

PREFIX=/usr/local
TMP="$(mktemp -d)" || exit 1
trap 'rm -rf "${TMP}"' EXIT
FAILED=0

fail() {
    echo "FAIL: $*" >&2
    FAILED=1
}

pass() {
    echo "ok: $*"
}

# Print the first X.Y.Z version in the first line of the command output.
version_of() {
    "$@" 2>&1 | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1
}

# The kvm wrapper adds -enable-kvm, which -version and help do not need.
for cmd in "kvm -version" "qemu-img --version" "qemu-nbd --version"; do
    # shellcheck disable=SC2086 # split the command and its argument
    v="$(version_of ${cmd})"
    if [ -z "${v}" ]; then
        fail "${cmd}: printed no QEMU version"
    elif [ "${MODE}" = upstream ] && [ "${v}" != "${EXPECTED}" ]; then
        fail "${cmd}: version ${v}, expected ${EXPECTED}"
    else
        pass "${cmd}: version ${v}"
    fi
done

if [ "${MODE}" = distro ]; then
    [ "${FAILED}" -eq 0 ] || { echo "QEMU checks failed" >&2; exit 1; }
    echo "QEMU checks passed (${MODE})"
    exit 0
fi

# has_line <file> <text>: a line of the file is exactly <text> after trimming
has_line() {
    awk -v want="$2" '{ gsub(/^[ \t]+|[ \t]+$/, "") } $0 == want { found = 1 } END { exit !found }' "$1"
}

# has_word <file> <word>: the first word of a line is <word>
has_word() {
    awk -v want="$2" '$1 == want { found = 1 } END { exit !found }' "$1"
}

check_machines() {
    arch="$1"
    shift
    bin="qemu-system-${arch}"
    out="${TMP}/${arch}-machines.txt"
    v="$(version_of "${bin}" -version)"
    if [ "${v}" != "${EXPECTED}" ]; then
        fail "${bin} -version: version ${v:-none}, expected ${EXPECTED}"
    else
        pass "${bin} -version: version ${v}"
    fi
    "${bin}" -machine help > "${out}" 2>&1
    status=$?
    if [ "${status}" -ne 0 ]; then
        fail "${bin} -machine help: exit status ${status}"
        return
    fi
    for m in "$@"; do
        if has_word "${out}" "${m}"; then
            pass "${bin} -machine help: lists ${m}"
        else
            fail "${bin} -machine help: does not list ${m}"
        fi
    done
}

check_machines x86_64 pc q35
check_machines i386 pc q35
check_machines arm mps2-an385
check_machines aarch64 virt

if qemu-system-x86_64 -device help > "${TMP}/devices.txt" 2>&1 \
    && grep -q '"qxl-vga"' "${TMP}/devices.txt"; then
    pass "qemu-system-x86_64 -device help: lists qxl-vga"
else
    fail "qemu-system-x86_64 -device help: does not list qxl-vga"
fi

if kvm -chardev help > "${TMP}/chardevs.txt" 2>&1 && has_line "${TMP}/chardevs.txt" qemu-vdagent; then
    pass "kvm -chardev help: lists qemu-vdagent"
else
    fail "kvm -chardev help: does not list qemu-vdagent"
fi

# start_vm <name> <QEMU arguments>: start a paused TCG VM in the background.
# This loads the modules and libraries that the arguments need.
start_vm() {
    name="$1"
    shift
    log="${TMP}/${name}.log"
    qemu-system-x86_64 -accel tcg -machine pc -display none -S \
        -daemonize -pidfile "${TMP}/${name}.pid" "$@" > "${log}" 2>&1
    status=$?
    if [ "${status}" -ne 0 ] || grep -qi 'not available' "${log}"; then
        fail "${name}: QEMU exit status ${status}: $(cat "${log}")"
        stop_vm "${name}"
        return 1
    fi
    pass "${name}: QEMU started"
}

# stop_vm <name>: stop a VM that start_vm started, and wait up to 10 seconds.
stop_vm() {
    [ -s "${TMP}/$1.pid" ] || return 0
    pid="$(cat "${TMP}/$1.pid")"
    kill "${pid}" 2>/dev/null || return 0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "${pid}" 2>/dev/null || return 0
        sleep 1
    done
    fail "$1: QEMU process ${pid} did not stop"
}

start_vm qxl -vga qxl && stop_vm qxl

if start_vm vnc -vnc "unix:${TMP}/vnc.sock"; then
    if [ -S "${TMP}/vnc.sock" ]; then
        pass "vnc: socket ${TMP}/vnc.sock exists"
    else
        fail "vnc: QEMU created no socket at ${TMP}/vnc.sock"
    fi
    stop_vm vnc
fi

# Every installed program, helper, and module must find its shared libraries.
checked=0
missing=0
for f in "${PREFIX}"/bin/qemu-* "${PREFIX}"/libexec/* "${PREFIX}"/lib/qemu/*.so; do
    [ -f "${f}" ] || continue
    checked=$((checked + 1))
    if ldd "${f}" 2>&1 | grep 'not found' > "${TMP}/missing.txt"; then
        fail "ldd ${f}: $(tr -s ' \t\n' ' ' < "${TMP}/missing.txt")"
        missing=1
    fi
done
if ! ls "${PREFIX}"/lib/qemu/*.so > /dev/null 2>&1; then
    fail "ldd: no QEMU modules in ${PREFIX}/lib/qemu"
elif [ "${missing}" -eq 0 ]; then
    pass "ldd: all libraries found for ${checked} files"
fi

[ "${FAILED}" -eq 0 ] || { echo "QEMU checks failed" >&2; exit 1; }
echo "QEMU checks passed (${MODE})"
