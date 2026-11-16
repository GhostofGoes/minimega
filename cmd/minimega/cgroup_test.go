// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// setCgroup points -cgroup at dir for the duration of a test.
func setCgroup(t *testing.T, dir string) {
	t.Helper()
	original := *f_cgroup
	t.Cleanup(func() { *f_cgroup = original })
	*f_cgroup = dir
}

func TestCgroupDirsV1(t *testing.T) {
	root := t.TempDir()
	setCgroup(t, root)

	if cgroupUnified() {
		t.Fatal("a temporary directory is not a cgroup v2")
	}

	if got, want := cgroupDir("freezer", "7"), filepath.Join(root, "freezer", "minimega", "7"); got != want {
		t.Errorf("cgroupDir: got %v, want %v", got, want)
	}

	want := []string{
		filepath.Join(root, "freezer", "minimega"),
		filepath.Join(root, "memory", "minimega"),
		filepath.Join(root, "devices", "minimega"),
		filepath.Join(root, "cpu", "minimega"),
	}
	if got := cgroupDirs(); !reflect.DeepEqual(got, want) {
		t.Errorf("cgroupDirs: got %v, want %v", got, want)
	}
}

func TestCgroupFreezeV1(t *testing.T) {
	root := t.TempDir()
	setCgroup(t, root)

	dir := cgroupDir("freezer", "3")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}

	for freeze, want := range map[bool]string{true: "FROZEN", false: "THAWED"} {
		if err := cgroupFreeze("3", freeze); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, "freezer.state"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("freeze %v: got %q, want %q", freeze, got, want)
		}
	}
}

// TestContainerInitError checks that every launch gets the reason for a failed
// cgroup setup, not only the first.
func TestContainerInitError(t *testing.T) {
	once, success, initErr := containerInitOnce, containerInitSuccess, containerInitErr
	t.Cleanup(func() { containerInitOnce, containerInitSuccess, containerInitErr = once, success, initErr })
	containerInitOnce, containerInitSuccess, containerInitErr = false, false, nil

	// no cgroup can be made below a file
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0644); err != nil {
		t.Fatal(err)
	}
	setCgroup(t, file)

	first := containerInit()
	if first == nil || containerInitSuccess {
		t.Fatalf("containerInit below a file: got %v, want an error", first)
	}
	if again := containerInit(); again != first {
		t.Errorf("second containerInit: got %v, want %v", again, first)
	}
}

func TestCgroupDelegate(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// the memory controller is disabled, or bound to a cgroup v1 hierarchy
	write("cgroup.controllers", "cpuset cpu io pids\n")
	if err := cgroupDelegate(dir); err == nil || !strings.Contains(err.Error(), "memory is not available") {
		t.Errorf("missing controller: got %v", err)
	}

	write("cgroup.controllers", "cpuset cpu io memory pids\n")
	if err := cgroupDelegate(dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "+cpu +memory"; string(got) != want {
		t.Errorf("subtree_control: got %q, want %q", got, want)
	}
}

// TestCgroupInitUnified runs the cgroup v2 setup on plain files.
func TestCgroupInitUnified(t *testing.T) {
	dir := t.TempDir()
	setCgroup(t, dir)
	write := func(name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// kernels before 5.2 have cgroup v2 without the freezer
	write("cgroup.controllers", "cpu memory\n")
	if err := cgroupInitUnified(); err == nil || !strings.Contains(err.Error(), "Linux 5.2") {
		t.Errorf("no cgroup.freeze: got %v", err)
	}

	write("minimega/cgroup.freeze", "0\n")
	write("minimega/cgroup.controllers", "cpu memory\n")
	if err := cgroupInitUnified(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cgroup.subtree_control", "minimega/cgroup.subtree_control"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if want := "+cpu +memory"; string(got) != want {
			t.Errorf("%v: got %q, want %q", name, got, want)
		}
	}
}

func TestCgroupUnifiedPath(t *testing.T) {
	for _, c := range []struct {
		in   string
		path string
		ok   bool
	}{
		{"0::/system.slice/minimega.service\n", "/system.slice/minimega.service", true},
		{"12:memory:/user.slice\n1:name=systemd:/user.slice/session-1.scope\n0::/user.slice/session-1.scope\n", "/user.slice/session-1.scope", true},
		{"0::/\n", "/", true},
		// cgroup v1 only
		{"4:memory:/\n1:name=systemd:/init.scope\n", "", false},
	} {
		path, ok := cgroupUnifiedPath(c.in)
		if path != c.path || ok != c.ok {
			t.Errorf("cgroupUnifiedPath(%q): got %q, %v, want %q, %v", c.in, path, ok, c.path, c.ok)
		}
	}
}

// TestCgroupInitUnifiedDelegated runs the cgroup v2 setup in a cgroup that is
// marked as delegated, as systemd does with Delegate=yes, and holds the test.
// It needs root and a cgroup v2 mount.
func TestCgroupInitUnifiedDelegated(t *testing.T) {
	mount := cgroup2Mount()
	if os.Geteuid() != 0 || mount == "" {
		t.Skip("needs root and a cgroup v2 mount")
	}
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	own, ok := cgroupUnifiedPath(string(b))
	if !ok {
		t.Skip("not in a cgroup v2")
	}
	setCgroup(t, mount)

	pid := []byte(strconv.Itoa(os.Getpid()))
	root := filepath.Join(mount, fmt.Sprintf("minimega-test-delegated-%d", os.Getpid()))
	if err := os.Mkdir(root, 0755); err != nil {
		t.Skipf("unable to create a cgroup: %v", err)
	}
	t.Cleanup(func() {
		cgroupRoot.Store(nil)
		if err := os.WriteFile(filepath.Join(mount, own, "cgroup.procs"), pid, 0644); err != nil {
			t.Errorf("move the test back to %v: %v", own, err)
		}
		for _, d := range []string{"minimega", "init", ""} {
			if err := cgroupRemove(filepath.Join(root, d)); err != nil && !os.IsNotExist(err) {
				t.Errorf("remove cgroup: %v", err)
			}
		}
	})

	if err := unix.Setxattr(root, "trusted.delegate", []byte("1"), 0); err != nil {
		t.Skipf("unable to mark the cgroup as delegated: %v", err)
	}
	if !cgroupDelegated(root) {
		t.Fatal("cgroupDelegated: got false for trusted.delegate=1")
	}

	// the test is not in the delegated cgroup yet
	if dir, ok := cgroupOwnDelegated(); ok {
		t.Fatalf("cgroupOwnDelegated outside of %v: got %v", root, dir)
	}

	if err := os.WriteFile(filepath.Join(root, "cgroup.procs"), pid, 0644); err != nil {
		t.Fatal(err)
	}
	if dir, ok := cgroupOwnDelegated(); !ok || dir != root {
		t.Fatalf("cgroupOwnDelegated: got %v, %v, want %v, true", dir, ok, root)
	}

	// a child process of minimega, such as a QEMU, moves too
	sleep := exec.Command("sleep", "60")
	if err := sleep.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		sleep.Process.Kill()
		sleep.Wait()
	}()

	err = cgroupInitUnified()
	// the controllers may be bound to cgroup v1 (a hybrid hierarchy)
	if err != nil && !strings.Contains(err.Error(), "is not available") {
		t.Fatal(err)
	}

	if got := cgroupDir("", "3"); got != filepath.Join(root, "minimega", "3") {
		t.Errorf("cgroupDir: got %v", got)
	}
	procs := func(dir string) []string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Fields(string(b))
		slices.Sort(got)
		return got
	}
	if got := procs(root); len(got) != 0 {
		t.Errorf("processes left in %v: %v", root, got)
	}
	want := []string{string(pid), strconv.Itoa(sleep.Process.Pid)}
	slices.Sort(want)
	if got := procs(filepath.Join(root, "init")); !reflect.DeepEqual(got, want) {
		t.Errorf("processes in init: got %v, want %v", got, want)
	}

	// init is not delegated
	if dir, ok := cgroupOwnDelegated(); ok {
		t.Errorf("cgroupOwnDelegated in init: got %v", dir)
	}

	if err == nil {
		if _, err := os.Stat(filepath.Join(root, "minimega", "cgroup.freeze")); err != nil {
			t.Error(err)
		}
	}
}

func TestParseDeviceRule(t *testing.T) {
	const r, w, m = unix.BPF_DEVCG_ACC_READ, unix.BPF_DEVCG_ACC_WRITE, unix.BPF_DEVCG_ACC_MKNOD

	valid := map[string]deviceRule{
		"c 1:3 rwm":   {Type: unix.BPF_DEVCG_DEV_CHAR, Major: 1, Minor: 3, Access: r | w | m},
		"c 1:1 r":     {Type: unix.BPF_DEVCG_DEV_CHAR, Major: 1, Minor: 1, Access: r},
		"c 136:* rwm": {Type: unix.BPF_DEVCG_DEV_CHAR, Major: 136, Minor: -1, Access: r | w | m},
		"b *:* m":     {Type: unix.BPF_DEVCG_DEV_BLOCK, Major: -1, Minor: -1, Access: m},
		"a *:* rw":    {Major: -1, Minor: -1, Access: r | w},
	}
	for s, want := range valid {
		got, err := parseDeviceRule(s)
		if err != nil {
			t.Errorf("%q: %v", s, err)
		} else if got != want {
			t.Errorf("%q: got %+v, want %+v", s, got, want)
		}
	}

	for _, s := range []string{"", "c 1:3", "x 1:3 rwm", "c 13 rwm", "c 1:-3 rwm", "c one:3 rwm", "c 1:3 rwx"} {
		if _, err := parseDeviceRule(s); err == nil {
			t.Errorf("%q: expected an error", s)
		}
	}

	// every rule that containers use must parse
	for _, s := range containerDevices {
		if _, err := parseDeviceRule(s); err != nil {
			t.Errorf("containerDevices: %v", err)
		}
	}
}

// bpfRun interprets the instructions that cgroupDeviceProgram emits, with
// ctx as the struct bpf_cgroup_dev_ctx in r1, and returns r0.
func bpfRun(t *testing.T, prog []bpfInsn, ctx [3]uint32) uint64 {
	t.Helper()

	var reg [6]uint64
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]

		dst, src := in.Regs&0xf, in.Regs>>4
		if bpfRegs(1, 0) != 1 {
			dst, src = src, dst
		}
		if dst > 5 || src > 5 {
			t.Fatalf("instruction %d: unexpected register in %+v", pc, in)
		}

		switch in.Code {
		case bpfLoad:
			if src != 1 || in.Off%4 != 0 || in.Off < 0 || in.Off > 8 {
				t.Fatalf("instruction %d: load outside of the context: %+v", pc, in)
			}
			reg[dst] = uint64(ctx[in.Off/4])
		case bpfAnd:
			reg[dst] = uint64(uint32(reg[dst]) & uint32(in.Imm))
		case bpfRsh:
			reg[dst] = uint64(uint32(reg[dst]) >> uint32(in.Imm))
		case bpfMovReg:
			reg[dst] = uint64(uint32(reg[src]))
		case bpfMov:
			reg[dst] = uint64(int64(in.Imm))
		case bpfJmpNe:
			if in.Off < 0 {
				t.Fatalf("instruction %d: backward jump: %+v", pc, in)
			}
			if reg[dst] != uint64(int64(in.Imm)) {
				pc += int(in.Off)
			}
		case bpfExit:
			return reg[0]
		default:
			t.Fatalf("instruction %d: unexpected %+v", pc, in)
		}
	}

	t.Fatal("program did not exit")
	return 0
}

func TestCgroupDeviceProgram(t *testing.T) {
	const (
		char, block = unix.BPF_DEVCG_DEV_CHAR, unix.BPF_DEVCG_DEV_BLOCK
		r, w, m     = unix.BPF_DEVCG_ACC_READ, unix.BPF_DEVCG_ACC_WRITE, unix.BPF_DEVCG_ACC_MKNOD
	)

	prog, err := cgroupDeviceProgram(containerDevices)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		typ, access  uint32
		major, minor uint32
		allow        bool
	}{
		{"read /dev/null", char, r, 1, 3, true},
		{"read and write /dev/null", char, r | w, 1, 3, true},
		{"mknod /dev/null", char, m, 1, 3, true},
		{"write /dev/urandom", char, w, 1, 9, true},
		{"read /dev/mem", char, r, 1, 1, false},
		{"mknod /dev/mem", char, m, 1, 1, true},
		{"mknod and read /dev/mem", char, m | r, 1, 1, false},
		{"read /dev/kmsg", char, r, 1, 11, false},
		{"read /dev/tty1", char, r | w, 4, 1, true},
		{"read /dev/tty2", char, r | w, 4, 2, false},
		{"read /dev/console", char, r | w, 5, 1, true},
		{"write a pty", char, r | w, 136, 42, true},
		{"read /dev/net/tun", char, r | w, 10, 200, true},
		{"read /dev/fuse", char, r | w, 10, 229, false},
		{"read /dev/kvm", char, r | w, 10, 232, false},
		{"read /dev/sda", block, r, 8, 0, false},
		{"write /dev/sda", block, w, 8, 0, false},
		{"mknod /dev/sda", block, m, 8, 0, true},
		{"read a block device with the numbers of /dev/null", block, r, 1, 3, false},
		{"read /dev/loop0", block, r | w, 7, 0, false},
	}
	for _, tt := range tests {
		ctx := [3]uint32{tt.access<<16 | tt.typ, tt.major, tt.minor}
		if got := bpfRun(t, prog, ctx) == 1; got != tt.allow {
			t.Errorf("%v: allowed = %v, want %v", tt.name, got, tt.allow)
		}
	}

	// the first rule that matches everything ends the program
	prog, err = cgroupDeviceProgram([]string{"c 1:3 r", "a *:* rwm", "c 1:5 r"})
	if err != nil {
		t.Fatal(err)
	}
	if got := bpfRun(t, prog, [3]uint32{w<<16 | block, 8, 0}); got != 1 {
		t.Errorf("allow all: got %v", got)
	}
	if allow := prog[len(prog)-2]; allow.Code != bpfMov || allow.Imm != 1 {
		t.Errorf("unreachable instructions after the rule that allows all")
	}

	// no rules deny everything
	prog, err = cgroupDeviceProgram(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := bpfRun(t, prog, [3]uint32{r<<16 | char, 1, 3}); got != 0 {
		t.Errorf("deny all: got %v", got)
	}

	if _, err := cgroupDeviceProgram([]string{"c 1:3 rwm", "bogus"}); err == nil {
		t.Error("expected an error for an invalid rule")
	}
}

// skipUnprivileged skips a test if err says that it may not use eBPF, as root
// in a container without privileges (a Docker build) may not.
func skipUnprivileged(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, unix.EPERM) {
		t.Skipf("needs CAP_BPF or CAP_SYS_ADMIN: %v", err)
	}
}

// TestCgroupDeviceProgramLoad checks that the kernel's verifier accepts the
// program. It needs root.
func TestCgroupDeviceProgramLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}

	for name, rules := range map[string][]string{
		"containers": containerDevices,
		"allow all":  {"c 1:3 r", "a *:* rwm", "c 1:5 r"},
		"deny all":   nil,
	} {
		prog, err := cgroupDeviceProgram(rules)
		if err != nil {
			t.Fatal(err)
		}

		fd, err := bpfLoadDeviceProgram(prog)
		if err != nil {
			skipUnprivileged(t, err)
			t.Errorf("%v: %v", name, err)
			continue
		}
		unix.Close(fd)
	}
}

// TestCgroupDeviceProgramLoadSignal checks that a load survives signals, which
// stop the kernel's verifier with EAGAIN. It needs root.
func TestCgroupDeviceProgramLoadSignal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}

	prog, err := cgroupDeviceProgram(containerDevices)
	if err != nil {
		t.Fatal(err)
	}

	// the signals go to one thread, so stay on it
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	load := func() time.Duration {
		t.Helper()
		start := time.Now()
		fd, err := bpfLoadDeviceProgram(prog)
		if err != nil {
			skipUnprivileged(t, err)
			t.Fatal(err)
		}
		unix.Close(fd)
		return time.Since(start)
	}

	// leave time for some loads between two signals, so that a retry can pass
	pause := load()
	for i := 0; i < 5; i++ {
		pause = min(pause, load())
	}
	pause *= 10

	var sent atomic.Int32
	pid, tid := os.Getpid(), unix.Gettid()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(pause):
				// the Go runtime ignores a SIGURG that it did not ask for
				unix.Tgkill(pid, tid, unix.SIGURG)
				sent.Add(1)
			}
		}
	}()
	defer func() { close(stop); <-done }()

	for sent.Load() < 50 {
		load()
	}
}

// cgroup2Mount returns where a cgroup v2 hierarchy is mounted, if anywhere.
func cgroup2Mount() string {
	b, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 2 && f[2] == "cgroup2" {
			return f[1]
		}
	}

	return ""
}

// TestCgroupUnified creates a cgroup v2, filters its devices, and freezes a
// process in it.
// It needs root and a cgroup v2 mount.
func TestCgroupUnified(t *testing.T) {
	mount := cgroup2Mount()
	if os.Geteuid() != 0 || mount == "" {
		t.Skip("needs root and a cgroup v2 mount")
	}

	root := filepath.Join(mount, fmt.Sprintf("minimega-test-%d", os.Getpid()))
	if err := os.Mkdir(root, 0755); err != nil {
		t.Skipf("unable to create a cgroup: %v", err)
	}
	setCgroup(t, root)

	const id = "0"
	dir := filepath.Join(root, "minimega", id)
	t.Cleanup(func() {
		for _, d := range []string{dir, filepath.Dir(dir), root} {
			if err := cgroupRemove(d); err != nil && !os.IsNotExist(err) {
				t.Errorf("remove cgroup: %v", err)
			}
		}
	})

	if !cgroupUnified() {
		t.Fatalf("%v is a cgroup v2", root)
	}

	if got := cgroupDir("", id); got != dir {
		t.Fatalf("cgroupDir: got %v, want %v", got, dir)
	}
	if got := cgroupDirs(id); !reflect.DeepEqual(got, []string{dir}) {
		t.Errorf("cgroupDirs: got %v", got)
	}
	if err := os.Mkdir(filepath.Dir(dir), 0755); err != nil {
		t.Fatal(err)
	}
	if err := cgroupCreate(dir); err != nil {
		t.Fatal(err)
	}

	if err := cgroupDeviceFilter(dir, containerDevices); err != nil {
		skipUnprivileged(t, err)
		t.Fatal(err)
	}

	// run starts a command in the cgroup
	cgroup, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()
	run := func(args ...string) *exec.Cmd {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
		return cmd
	}

	// devices: /dev/null is allowed, a new node for /dev/mem may be made but not
	// opened. The node is in /dev because a temporary directory may be nodev.
	if out, err := run("sh", "-c", ": < /dev/null").CombinedOutput(); err != nil {
		t.Errorf("open /dev/null: %v: %s", err, out)
	}
	mem := fmt.Sprintf("/dev/minimega-test-mem-%d", os.Getpid())
	defer os.Remove(mem)
	if out, err := run("mknod", mem, "c", "1", "1").CombinedOutput(); err != nil {
		t.Errorf("mknod: %v: %s", err, out)
	} else if out, err := run("sh", "-c", ": < "+mem).CombinedOutput(); err == nil {
		t.Errorf("open of a device that no rule allows succeeded: %s", out)
	} else if !strings.Contains(string(out), "not permitted") {
		t.Errorf("open of a device that no rule allows: %v: %s", err, out)
	}

	// freezer
	sleep := run("sleep", "60")
	if err := sleep.Start(); err != nil {
		t.Fatal(err)
	}
	stop := sync.OnceFunc(func() {
		sleep.Process.Kill()
		sleep.Wait()
	})
	defer stop()

	procs, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(procs)), fmt.Sprint(sleep.Process.Pid); got != want {
		t.Errorf("cgroup.procs: got %q, want %q", got, want)
	}

	for _, freeze := range []bool{true, false} {
		if err := cgroupFreeze(id, freeze); err != nil {
			t.Fatal(err)
		}

		want := "frozen 0"
		if freeze {
			want = "frozen 1"
		}
		var events []byte
		for i := 0; i < 100; i++ {
			events, _ = os.ReadFile(filepath.Join(dir, "cgroup.events"))
			if strings.Contains(string(events), want) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !strings.Contains(string(events), want) {
			t.Errorf("freeze %v: cgroup.events is %q", freeze, events)
		}
	}

	// a cgroup with processes is not reused, an empty one is replaced
	if err := cgroupCreate(dir); err == nil || !strings.Contains(err.Error(), "has processes") {
		t.Errorf("cgroupCreate with a process in the cgroup: %v", err)
	}
	stop()
	if err := cgroupCreate(dir); err != nil {
		t.Errorf("cgroupCreate with an empty cgroup: %v", err)
	}
}
