#!/usr/bin/env bash
# Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
# rights in this software.
#
# Run the minimega live integration tests against a Docker image.
#
#   sudo tests/live/run.sh [image]
#
# Steps:
#   1. pull the image (the one CI published, by default)
#   2. build the KVM guest kernel/initrd inside that image (tests/live/image)
#   3. start minimega from the image exactly as docker/README.md documents
#   4. load tests/live/topology.mm with "mm read" (the CLI path)
#   5. run the Go tests in tests/live over the command socket (the phenix path)
#   6. collect diagnostics, tear the experiment down, and stop the container
#
# Requirements: Linux, root, Docker, /dev/kvm, the openvswitch kernel module,
# and Go (unless LIVE_TEST_BIN points at a prebuilt test binary).
#
# Environment:
#   LIVE_IMAGE            image to test (default: first argument, then
#                         ghcr.io/sandia-minimega/minimega:master)
#   LIVE_PULL=0           use a local image without pulling
#   LIVE_CONTAINER        container name (default: minimega)
#   LIVE_MM_BASE          minimega base dir, same path on host and in the
#                         container (default: /tmp/minimega)
#   LIVE_ARTIFACTS        output directory (default: ./live-artifacts)
#   LIVE_TEST_BIN         prebuilt "go test -c -tags live" binary
#   LIVE_TEST_ARGS        extra arguments for the test binary (e.g. -test.run)
#   LIVE_KEEP=1           leave the experiment and container running
#   LIVE_FORCE=1          replace an existing container/base directory

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

IMAGE="${1:-${LIVE_IMAGE:-ghcr.io/sandia-minimega/minimega:master}}"
CONTAINER="${LIVE_CONTAINER:-minimega}"
MM_BASE="${LIVE_MM_BASE:-/tmp/minimega}"
MM_FILES="${MM_BASE}/files"
STAGE="${MM_FILES}/live"
ARTIFACTS="$(mkdir -p "${LIVE_ARTIFACTS:-${PWD}/live-artifacts}" && cd "${LIVE_ARTIFACTS:-${PWD}/live-artifacts}" && pwd)"
NAMESPACE=live

log() { echo "==> [$(date +%H:%M:%S)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }
mm() { docker exec -i "${CONTAINER}" minimega -e "$@"; }

# --- preflight ---------------------------------------------------------------

[[ "$(id -u)" == "0" ]] || die "run as root (the minimega socket and KVM need it)"
command -v docker >/dev/null || die "docker not found"
[[ -c /dev/kvm ]] || die "/dev/kvm not found; KVM is required"

if docker inspect "${CONTAINER}" >/dev/null 2>&1 || [[ -S "${MM_BASE}/minimega" ]]; then
	[[ "${LIVE_FORCE:-0}" == "1" ]] || die "container ${CONTAINER} or ${MM_BASE}/minimega exists; set LIVE_FORCE=1 to replace it"
	docker rm -f "${CONTAINER}" >/dev/null 2>&1
fi
rm -rf "${MM_BASE}"
mkdir -p "${STAGE}" "${ARTIFACTS}/logs"

# kvm/openvswitch must be loadable on the host; the container shares the kernel
modprobe openvswitch 2>/dev/null || true
lsmod | grep -q '^openvswitch' || log "warning: openvswitch module not loaded; Open vSwitch may fail to start"

# --- image -------------------------------------------------------------------

if [[ "${LIVE_PULL:-1}" == "1" ]]; then
	log "pulling ${IMAGE}"
	docker pull -q "${IMAGE}" || die "unable to pull ${IMAGE}"
fi
docker image inspect "${IMAGE}" --format 'image {{.Id}} created {{.Created}}' | tee "${ARTIFACTS}/image.txt"

log "building guest image"
docker run --rm \
	-v "${SCRIPT_DIR}/image:/src:ro" \
	-v "${STAGE}:/out" \
	"${IMAGE}" bash /src/build.sh /out > "${ARTIFACTS}/logs/guest-build.log" 2>&1 \
	|| { tail -50 "${ARTIFACTS}/logs/guest-build.log"; die "guest image build failed"; }
tail -2 "${ARTIFACTS}/logs/guest-build.log"
cp "${SCRIPT_DIR}/topology.mm" "${STAGE}/topology.mm"

# --- test binary -------------------------------------------------------------

TEST_BIN="${LIVE_TEST_BIN:-}"
if [[ -z "${TEST_BIN}" ]]; then
	command -v go >/dev/null || die "go not found; set LIVE_TEST_BIN"
	TEST_BIN="$(mktemp -d)/live.test"
	log "compiling tests"
	(cd "${ROOT_DIR}" && GOFLAGS=-mod=vendor go test -c -tags live -o "${TEST_BIN}" ./tests/live) || die "compile failed"
fi

# --- start minimega ----------------------------------------------------------

cleanup() {
	if [[ "${LIVE_KEEP:-0}" == "1" ]]; then
		log "LIVE_KEEP=1: leaving ${CONTAINER} running"
		return
	fi
	docker logs "${CONTAINER}" > "${ARTIFACTS}/logs/container.log" 2>&1 || true
	docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Same flags as docker/README.md, plus the hostname topology.mm schedules on
# and a host-visible log file.
log "starting ${CONTAINER}"
docker run -d \
	--name "${CONTAINER}" \
	--hostname minimega \
	--privileged \
	--cap-add ALL \
	-p 9000:9000/udp \
	-p 9001:9001 \
	-v /dev:/dev \
	-v /lib/modules:/lib/modules:ro \
	-v "${ARTIFACTS}/logs:/var/log/minimega" \
	-v "${MM_BASE}:${MM_BASE}" \
	-e MM_BASE="${MM_BASE}" \
	-e MM_FILEPATH="${MM_FILES}" \
	-e MM_LOGFILE=/var/log/minimega/minimega.log \
	-e MM_LOGLEVEL="${LIVE_LOGLEVEL:-info}" \
	--health-cmd "mm version" \
	"${IMAGE}" >/dev/null || die "unable to start container"

for _ in $(seq 1 60); do
	mm version >/dev/null 2>&1 && break
	sleep 2
done
mm version || { docker logs "${CONTAINER}" | tail -50; die "minimega did not start"; }

# --- load the topology through the CLI ---------------------------------------

log "loading topology.mm"
start=$(date +%s)
mm read "${STAGE}/topology.mm" 2>&1 | tee "${ARTIFACTS}/logs/topology-read.log"
if grep -q '^Error' "${ARTIFACTS}/logs/topology-read.log"; then
	mm namespace "${NAMESPACE}" .columns name,state,tags vm info || true
	die "topology.mm reported errors"
fi
log "topology loaded in $(( $(date +%s) - start ))s"

# --- run the tests -----------------------------------------------------------

export LIVE_MM_BASE="${MM_BASE}" LIVE_MM_FILES="${MM_FILES}" LIVE_CONTAINER="${CONTAINER}"
export LIVE_NAMESPACE="${NAMESPACE}" LIVE_ARTIFACTS="${ARTIFACTS}"

log "running tests"
# shellcheck disable=SC2086
"${TEST_BIN}" -test.v -test.timeout 60m -test.skip 'TestLive/ClearNamespace$' ${LIVE_TEST_ARGS:-} \
	2>&1 | tee "${ARTIFACTS}/live-test.log"
status=${PIPESTATUS[0]}

# --- diagnostics -------------------------------------------------------------

log "collecting diagnostics"
{
	echo "## vm info"; mm namespace "${NAMESPACE}" .columns name,state,cc_active,vlan,ip,tap,qos,tags vm info
	echo "## cc clients"; mm namespace "${NAMESPACE}" cc clients
	echo "## vlans"; mm namespace "${NAMESPACE}" vlans
	echo "## taps"; mm namespace "${NAMESPACE}" tap
	echo "## router rtr-ab"; mm namespace "${NAMESPACE}" router rtr-ab
	echo "## router rtr-cd"; mm namespace "${NAMESPACE}" router rtr-cd
	echo "## host"; mm host
	echo "## ovs"; docker exec "${CONTAINER}" ovs-vsctl show
} > "${ARTIFACTS}/diagnostics.txt" 2>&1
cp -r "${MM_FILES}/${NAMESPACE}/miniccc_responses" "${ARTIFACTS}/" 2>/dev/null || true

if [[ "${LIVE_KEEP:-0}" != "1" ]]; then
	log "tearing down"
	"${TEST_BIN}" -test.v -test.run 'TestLive/ClearNamespace$' 2>&1 | tee -a "${ARTIFACTS}/live-test.log"
	[[ ${PIPESTATUS[0]} -eq 0 ]] || status=1
fi

# Markdown summary of every test (and the GitHub job summary in CI)
{
	echo "### minimega live tests: $([[ ${status} -eq 0 ]] && echo passed || echo FAILED)"
	echo
	echo "Image: \`${IMAGE}\`"
	echo
	echo "| result | test | time |"
	echo "|---|---|---|"
	grep -E '^\s*--- (PASS|FAIL|SKIP): TestLive/' "${ARTIFACTS}/live-test.log" |
		sed -E 's/^\s*--- (PASS|FAIL|SKIP): TestLive\/(\S+) \(([^)]*)\).*/| \1 | \2 | \3 |/' |
		sed -e 's/^| PASS/| ✅ pass/' -e 's/^| FAIL/| ❌ fail/' -e 's/^| SKIP/| ⏭️ skip/'
	echo
	echo "Totals: $(grep -cE '^\s*--- PASS: TestLive/' "${ARTIFACTS}/live-test.log") passed," \
		"$(grep -cE '^\s*--- FAIL: TestLive/' "${ARTIFACTS}/live-test.log") failed," \
		"$(grep -cE '^\s*--- SKIP: TestLive/' "${ARTIFACTS}/live-test.log") skipped"
} > "${ARTIFACTS}/summary.md"
[[ -n "${GITHUB_STEP_SUMMARY:-}" ]] && cat "${ARTIFACTS}/summary.md" >> "${GITHUB_STEP_SUMMARY}"

if [[ ${status} -eq 0 ]]; then
	log "PASS"
else
	log "FAIL (see ${ARTIFACTS})"
fi
exit "${status}"
