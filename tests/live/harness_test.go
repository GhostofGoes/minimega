// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

//go:build live

// Package live holds end-to-end tests that drive a real, running minimega
// deployment (normally the published Docker image) over its command socket,
// the same way phenix does. They are excluded from regular builds by the
// "live" build tag; see tests/live/README.md and tests/live/run.sh.
package live

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandia-minimega/minimega/v2/pkg/minicli"
	"github.com/sandia-minimega/minimega/v2/pkg/miniclient"
)

// Environment knobs. Defaults match tests/live/run.sh and the Docker
// deployment described in docker/README.md.
var (
	// minimega -base directory holding the command socket (bind-mounted
	// from the container).
	mmBase = envOr("LIVE_MM_BASE", "/tmp/minimega")
	// minimega -filepath directory (bind-mounted from the container).
	mmFiles = envOr("LIVE_MM_FILES", filepath.Join(mmBase, "files"))
	// namespace created by topology.mm
	namespace = envOr("LIVE_NAMESPACE", "live")
	// Docker container running minimega; used for host-side assertions
	// (Open vSwitch, host taps, processes). Empty disables those checks.
	container = envOr("LIVE_CONTAINER", "minimega")
	// URL where miniweb is reachable from the test host.
	miniwebURL = envOr("LIVE_MINIWEB_URL", "http://127.0.0.1:9001")
	// directory for artifacts worth keeping (screenshots, pcaps)
	artifactDir = envOr("LIVE_ARTIFACTS", filepath.Join(os.TempDir(), "minimega-live-artifacts"))
	// how long to wait for the topology to settle (boot, DHCP, OSPF)
	settleTimeout = envDuration("LIVE_SETTLE_TIMEOUT", 6*time.Minute)
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// mm is a thin wrapper around miniclient that runs commands in the test
// namespace and turns responses into errors and tables.
type mm struct {
	conn *miniclient.Conn
}

var client *mm

func dial() (*mm, error) {
	conn, err := miniclient.Dial(mmBase)
	if err != nil {
		return nil, fmt.Errorf("dial minimega at %v: %w", mmBase, err)
	}
	return &mm{conn: conn}, nil
}

// raw runs a command exactly as given and returns every response from every
// host. Command errors are joined into the returned error.
func (m *mm) raw(cmd string) (minicli.Responses, error) {
	var out minicli.Responses
	var errs []string

	for r := range m.conn.Run(cmd) {
		if r.Status {
			continue
		}
		for _, resp := range r.Resp {
			if resp.Error != "" {
				errs = append(errs, fmt.Sprintf("%v: %v", resp.Host, resp.Error))
			}
			out = append(out, resp)
		}
	}

	if err := m.conn.Error(); err != nil {
		// the socket broke; reconnect so later subtests still get a chance
		if c, derr := dial(); derr == nil {
			m.conn = c.conn
		}
		return out, fmt.Errorf("%q: connection error: %w", cmd, err)
	}

	if len(errs) > 0 {
		return out, fmt.Errorf("%q: %v", cmd, strings.Join(errs, "; "))
	}

	return out, nil
}

// run runs a command in the test namespace.
func (m *mm) run(cmd string) (minicli.Responses, error) {
	return m.raw(fmt.Sprintf("namespace %v %v", namespace, cmd))
}

// text runs a command and returns the concatenated simple responses.
func (m *mm) text(cmd string) (string, error) {
	resps, err := m.run(cmd)
	var b strings.Builder
	for _, r := range resps {
		b.WriteString(r.Response)
	}
	return b.String(), err
}

// row is one tabular row keyed by column header. The responding host is
// stored under "host".
type row map[string]string

// table runs a command and flattens tabular responses from all hosts.
func (m *mm) table(cmd string) ([]row, error) {
	resps, err := m.run(cmd)
	return toRows(resps), err
}

func toRows(resps minicli.Responses) []row {
	var rows []row
	for _, r := range resps {
		for _, t := range r.Tabular {
			rw := row{"host": r.Host}
			for i, h := range r.Header {
				if i < len(t) {
					rw[h] = t[i]
				}
			}
			rows = append(rows, rw)
		}
	}
	return rows
}

// must* helpers fail the current test on error.

func mustRun(t *testing.T, cmd string) minicli.Responses {
	t.Helper()
	resps, err := client.run(cmd)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}
	return resps
}

func mustText(t *testing.T, cmd string) string {
	t.Helper()
	s, err := client.text(cmd)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}
	return s
}

func mustTable(t *testing.T, cmd string) []row {
	t.Helper()
	rows, err := client.table(cmd)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}
	return rows
}

// vmInfo returns "vm info" rows keyed by VM name.
func vmInfo(t *testing.T) map[string]row {
	t.Helper()
	vms := map[string]row{}
	for _, r := range mustTable(t, "vm info") {
		vms[r["name"]] = r
	}
	return vms
}

// eventually retries fn until it succeeds or the timeout expires.
func eventually(t *testing.T, timeout, interval time.Duration, fn func() error) {
	t.Helper()
	if err := poll(timeout, interval, fn); err != nil {
		t.Fatalf("condition not met after %v: %v", timeout, err)
	}
}

func poll(timeout, interval time.Duration, fn func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := fn()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(interval)
	}
}

// list parses minimega's "[a, b]" list formatting.
func list(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// --- command and control ---------------------------------------------------

var ccSeq atomic.Int64

// ccResult is the outcome of one cc command on one VM.
type ccResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// ccRun issues a cc command (e.g. `exec hostname`, `send foo`) filtered to the
// given cc filter and waits until `want` clients have responded. It returns
// per-VM results read from the miniccc_responses directory and the command ID.
func ccRun(t *testing.T, filter, command string, want int, timeout time.Duration) (map[string]ccResult, int) {
	t.Helper()

	prefix := fmt.Sprintf("live%d", ccSeq.Add(1))

	mustRun(t, "clear cc filter")
	if filter != "" {
		mustRun(t, "cc filter "+filter)
	}
	mustRun(t, "cc prefix "+prefix)
	_, err := client.run("cc " + command)
	// always reset shared cc state before checking the error
	client.run("clear cc prefix")
	client.run("clear cc filter")
	if err != nil {
		t.Fatalf("cc %v: %v", command, err)
	}

	id := -1
	eventually(t, timeout, 2*time.Second, func() error {
		for _, r := range mustTable(t, "cc commands") {
			if r["prefix"] != prefix {
				continue
			}
			id, _ = strconv.Atoi(r["id"])
			n, _ := strconv.Atoi(r["responses"])
			if n >= want {
				return nil
			}
			return fmt.Errorf("cc command %v (%v): %d/%d responses", id, command, n, want)
		}
		return fmt.Errorf("cc command with prefix %v not found", prefix)
	})

	return ccResponses(t, id), id
}

// ccResponses reads per-client responses for a command from disk and maps
// them from client UUID to VM name.
func ccResponses(t *testing.T, id int) map[string]ccResult {
	t.Helper()

	byUUID := map[string]string{}
	for name, r := range vmInfo(t) {
		byUUID[r["uuid"]] = name
	}

	dir := filepath.Join(mmFiles, namespace, "miniccc_responses", strconv.Itoa(id))
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read responses: %v", err)
	}

	res := map[string]ccResult{}
	for _, e := range entries {
		name := byUUID[e.Name()]
		if name == "" {
			name = e.Name()
		}
		read := func(f string) string {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name(), f))
			return string(b)
		}
		code := 0
		if s := strings.TrimSpace(read("exitcode")); s != "" {
			code, _ = strconv.Atoi(s)
		}
		res[name] = ccResult{Stdout: read("stdout"), Stderr: read("stderr"), ExitCode: code}
	}
	return res
}

// ccExec runs a shell command on exactly one VM and returns its result.
func ccExec(t *testing.T, vm, script string) ccResult {
	t.Helper()
	res, _ := ccRun(t, "name="+vm, fmt.Sprintf("exec sh -c %q", script), 1, 90*time.Second)
	r, ok := res[vm]
	if !ok {
		t.Fatalf("no cc response from %v (got %v)", vm, keys(res))
	}
	return r
}

// ccOK runs a shell command on one VM and fails the test unless it exits 0.
func ccOK(t *testing.T, vm, script string) string {
	t.Helper()
	r := ccExec(t, vm, script)
	if r.ExitCode != 0 {
		t.Fatalf("%v: `%v` exited %d\nstdout: %s\nstderr: %s", vm, script, r.ExitCode, r.Stdout, r.Stderr)
	}
	return r.Stdout
}

// ccEventually retries a shell command on one VM until it exits 0.
func ccEventually(t *testing.T, vm, script string, timeout time.Duration) string {
	t.Helper()
	var out string
	eventually(t, timeout, 3*time.Second, func() error {
		r := ccExec(t, vm, script)
		if r.ExitCode != 0 {
			return fmt.Errorf("%v: `%v` exited %d: %s%s", vm, script, r.ExitCode, r.Stdout, r.Stderr)
		}
		out = r.Stdout
		return nil
	})
	return out
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- host side ---------------------------------------------------------------

// inContainer runs a command inside the minimega container. Tests that need
// it are skipped when LIVE_CONTAINER is empty.
func inContainer(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if container == "" {
		t.Skip("LIVE_CONTAINER not set")
	}
	var out bytes.Buffer
	cmd := exec.Command("docker", append([]string{"exec", container}, args...)...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// artifact returns a path for a file worth keeping, creating its directory.
// The second return value is the same path as seen from inside minimega, for
// commands that write files (screenshots, captures).
func artifact(t *testing.T, name string) (host, mmPath string) {
	t.Helper()
	dir := filepath.Join(mmFiles, namespace, "artifacts")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	host = filepath.Join(dir, name)
	// mmFiles is bind-mounted at the same path inside the container
	mmPath = host
	return host, mmPath
}

// keep copies a file into the artifact directory uploaded by CI.
func keep(t *testing.T, src string) {
	t.Helper()
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		t.Logf("artifact dir: %v", err)
		return
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Logf("keep %v: %v", src, err)
		return
	}
	dst := filepath.Join(artifactDir, filepath.Base(src))
	if err := os.WriteFile(dst, b, 0644); err != nil {
		t.Logf("keep %v: %v", src, err)
	}
}
