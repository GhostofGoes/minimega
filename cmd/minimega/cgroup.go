// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Containers are confined by cgroups below the -cgroup mount. cgroup v1 has a
// hierarchy per controller (<cgroup>/<controller>/minimega/<vm id>), cgroup v2
// a single unified one (<cgroup>/minimega/<vm id>).

// cgroupControllers are the cgroup v1 controllers that containers use.
var cgroupControllers = []string{"freezer", "memory", "devices", "cpu"}

// cgroupUnifiedControllers are the cgroup v2 controllers that containers use.
// The freezer is part of cgroup v2 itself and devices are filtered with eBPF.
var cgroupUnifiedControllers = []string{"cpu", "memory"}

// cgroupUnified returns true if -cgroup is a cgroup v2 (unified) hierarchy.
func cgroupUnified() bool {
	var st unix.Statfs_t
	if err := unix.Statfs(*f_cgroup, &st); err != nil {
		return false
	}

	return st.Type == unix.CGROUP2_SUPER_MAGIC
}

// cgroupDir returns the cgroup of minimega, or of a VM if id is given, for a
// cgroup v1 controller. cgroup v2 has the same directory for all of them.
func cgroupDir(controller string, id ...string) string {
	elem := []string{*f_cgroup, controller, "minimega"}
	if cgroupUnified() {
		elem = []string{*f_cgroup, "minimega"}
	}

	return filepath.Join(append(elem, id...)...)
}

// cgroupDirs returns every cgroup of minimega, or of a VM if id is given.
func cgroupDirs(id ...string) []string {
	if cgroupUnified() {
		return []string{cgroupDir("", id...)}
	}

	var dirs []string
	for _, c := range cgroupControllers {
		dirs = append(dirs, cgroupDir(c, id...))
	}

	return dirs
}

// cgroupInitUnified creates the minimega cgroup on cgroup v2 and delegates the
// controllers that limit containers to it.
func cgroupInitUnified() error {
	// clean potentially old cgroup noise
	containerCleanCgroupDirs()

	if err := cgroupDelegate(*f_cgroup); err != nil {
		return err
	}

	dir := cgroupDir("")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cgroup mkdir: %v", err)
	}

	// minimega pauses containers with the freezer of Linux 5.2
	if _, err := os.Stat(filepath.Join(dir, "cgroup.freeze")); err != nil {
		return fmt.Errorf("cgroup v2 needs Linux 5.2 or newer: %v", err)
	}

	return cgroupDelegate(dir)
}

// cgroupDelegate enables cgroupUnifiedControllers for the children of a
// cgroup v2.
func cgroupDelegate(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return err
	}

	have := strings.Fields(string(b))
	for _, c := range cgroupUnifiedControllers {
		if !slices.Contains(have, c) {
			return fmt.Errorf("cgroup v2 controller %v is not available in %v (has: %v)", c, dir, strings.Join(have, " "))
		}
	}

	enable := "+" + strings.Join(cgroupUnifiedControllers, " +")
	err = os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte(enable), 0644)
	if errors.Is(err, syscall.EBUSY) {
		// only the root cgroup may hold processes and have controllers for its children
		return fmt.Errorf("%v: move the processes in %v to a child cgroup, or set -cgroup", err, dir)
	}

	return err
}

// cgroupCreate makes a new cgroup v2 for a VM. It replaces an empty one, which
// a failed launch leaves with its device filter. One with processes belongs to
// another minimega, or to one that crashed, and stays.
func cgroupCreate(dir string) error {
	if err := cgroupRemove(dir); errors.Is(err, syscall.EBUSY) {
		return fmt.Errorf("cgroup %v has processes, the nuke command removes them: %v", dir, err)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}

	return os.Mkdir(dir, 0755)
}

// cgroupPopulateUnified creates the cgroup v2 of a VM, applies the VM's limits
// to it, and moves the calling process into it.
func cgroupPopulateUnified(vmID, vcpus, memory int) error {
	dir := cgroupDir("", strconv.Itoa(vmID))
	if err := cgroupCreate(dir); err != nil {
		return err
	}

	// devices
	if err := cgroupDeviceFilter(dir, containerDevices); err != nil {
		return fmt.Errorf("device filter: %v", err)
	}

	// CPU bandwidth, see containerPopulateCgroups: "<quota> <period>" in microseconds
	period := time.Second.Microseconds()
	quota := int64(vcpus) * period
	cpuMax := filepath.Join(dir, "cpu.max")
	if err := os.WriteFile(cpuMax, []byte(fmt.Sprintf("%v %v", quota, period)), 0644); err != nil {
		return err
	}

	// memory
	memMax := filepath.Join(dir, "memory.max")
	if err := os.WriteFile(memMax, []byte(fmt.Sprintf("%vM", memory)), 0644); err != nil {
		return err
	}

	// associate the pid with these permissions
	procs := filepath.Join(dir, "cgroup.procs")
	return os.WriteFile(procs, []byte(strconv.Itoa(os.Getpid())), 0644)
}

// cgroupFreeze freezes or thaws every process of a VM.
func cgroupFreeze(id string, freeze bool) error {
	dir := cgroupDir("freezer", id)

	if cgroupUnified() {
		state := "0"
		if freeze {
			state = "1"
		}

		return os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte(state), 0644)
	}

	state := "THAWED"
	if freeze {
		state = "FROZEN"
	}

	return os.WriteFile(filepath.Join(dir, "freezer.state"), []byte(state), 0644)
}

// cgroupRemove removes a cgroup. A cgroup stays busy for a moment after its
// last process exits, so retry.
func cgroupRemove(dir string) error {
	var err error
	for i := 0; i < 10; i++ {
		if err = os.Remove(dir); !errors.Is(err, syscall.EBUSY) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return err
}

// deviceRule is one line of containerDevices, the format of the cgroup v1
// devices.allow file: "<a|b|c> <major|*>:<minor|*> <rwm>".
type deviceRule struct {
	Type   int32 // BPF_DEVCG_DEV_*, 0 for any
	Major  int32 // -1 for any
	Minor  int32 // -1 for any
	Access int32 // BPF_DEVCG_ACC_*
}

const deviceAccessAll = unix.BPF_DEVCG_ACC_MKNOD | unix.BPF_DEVCG_ACC_READ | unix.BPF_DEVCG_ACC_WRITE

func parseDeviceRule(s string) (deviceRule, error) {
	r := deviceRule{}

	f := strings.Fields(s)
	if len(f) != 3 {
		return r, fmt.Errorf("invalid device rule: %v", s)
	}

	switch f[0] {
	case "a":
	case "b":
		r.Type = unix.BPF_DEVCG_DEV_BLOCK
	case "c":
		r.Type = unix.BPF_DEVCG_DEV_CHAR
	default:
		return r, fmt.Errorf("invalid device type: %v", s)
	}

	number := func(v string) (int32, error) {
		if v == "*" {
			return -1, nil
		}
		n, err := strconv.ParseUint(v, 10, 31)
		return int32(n), err
	}

	major, minor, _ := strings.Cut(f[1], ":")
	var err1, err2 error
	r.Major, err1 = number(major)
	r.Minor, err2 = number(minor)
	if err1 != nil || err2 != nil {
		return r, fmt.Errorf("invalid device number: %v", s)
	}

	for _, c := range f[2] {
		switch c {
		case 'r':
			r.Access |= unix.BPF_DEVCG_ACC_READ
		case 'w':
			r.Access |= unix.BPF_DEVCG_ACC_WRITE
		case 'm':
			r.Access |= unix.BPF_DEVCG_ACC_MKNOD
		default:
			return r, fmt.Errorf("invalid device access: %v", s)
		}
	}

	return r, nil
}

// bpfInsn is an eBPF instruction, struct bpf_insn in linux/bpf.h.
type bpfInsn struct {
	Code uint8
	Regs uint8
	Off  int16
	Imm  int32
}

// bpfRegs packs the destination and source registers of an instruction. They
// are C bit-fields, so their order depends on the byte order.
func bpfRegs(dst, src uint8) uint8 {
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		return dst<<4 | src
	}

	return src<<4 | dst
}

const (
	bpfLoad   = unix.BPF_LDX | unix.BPF_MEM | unix.BPF_W   // dst = *(u32 *)(src + off)
	bpfAnd    = unix.BPF_ALU | unix.BPF_AND | unix.BPF_K   // dst &= imm
	bpfRsh    = unix.BPF_ALU | unix.BPF_RSH | unix.BPF_K   // dst >>= imm
	bpfMovReg = unix.BPF_ALU | unix.BPF_MOV | unix.BPF_X   // dst = src
	bpfMov    = unix.BPF_ALU64 | unix.BPF_MOV | unix.BPF_K // dst = imm
	bpfJmpNe  = unix.BPF_JMP | unix.BPF_JNE | unix.BPF_K   // if dst != imm goto +off
	bpfExit   = unix.BPF_JMP | unix.BPF_EXIT               // return r0
)

// cgroupDeviceProgram compiles device rules to an eBPF program for a cgroup
// v2, which has no devices controller. The program allows an access that a
// rule matches and denies any other, like devices.deny "a" then devices.allow
// for each rule on cgroup v1.
func cgroupDeviceProgram(rules []string) ([]bpfInsn, error) {
	// r1 is a struct bpf_cgroup_dev_ctx. Load the device type into r2, the
	// requested access into r3, and the major and minor numbers into r4 and r5.
	prog := []bpfInsn{
		{Code: bpfLoad, Regs: bpfRegs(2, 1)},
		{Code: bpfAnd, Regs: bpfRegs(2, 0), Imm: 0xffff},
		{Code: bpfLoad, Regs: bpfRegs(3, 1)},
		{Code: bpfRsh, Regs: bpfRegs(3, 0), Imm: 16},
		{Code: bpfLoad, Regs: bpfRegs(4, 1), Off: 4},
		{Code: bpfLoad, Regs: bpfRegs(5, 1), Off: 8},
	}
	allow := []bpfInsn{
		{Code: bpfMov, Imm: 1},
		{Code: bpfExit},
	}

	for _, s := range rules {
		r, err := parseDeviceRule(s)
		if err != nil {
			return nil, err
		}

		// each test skips to the next rule if this one does not match
		var rule []bpfInsn
		if r.Type != 0 {
			rule = append(rule, bpfInsn{Code: bpfJmpNe, Regs: bpfRegs(2, 0), Imm: r.Type})
		}
		if r.Access != deviceAccessAll {
			// r1 is free by now: use it for the access that the rule does not grant
			rule = append(rule,
				bpfInsn{Code: bpfMovReg, Regs: bpfRegs(1, 3)},
				bpfInsn{Code: bpfAnd, Regs: bpfRegs(1, 0), Imm: ^r.Access},
				bpfInsn{Code: bpfJmpNe, Regs: bpfRegs(1, 0)},
			)
		}
		if r.Major != -1 {
			rule = append(rule, bpfInsn{Code: bpfJmpNe, Regs: bpfRegs(4, 0), Imm: r.Major})
		}
		if r.Minor != -1 {
			rule = append(rule, bpfInsn{Code: bpfJmpNe, Regs: bpfRegs(5, 0), Imm: r.Minor})
		}

		if len(rule) == 0 {
			// matches everything: the verifier rejects the unreachable rest
			return append(prog, allow...), nil
		}

		rule = append(rule, allow...)
		for i := range rule {
			if rule[i].Code == bpfJmpNe {
				rule[i].Off = int16(len(rule) - i - 1)
			}
		}
		prog = append(prog, rule...)
	}

	// default deny
	return append(prog, bpfInsn{Code: bpfMov}, bpfInsn{Code: bpfExit}), nil
}

// bpfLoadAttempts is how often to load a program that a signal interrupts.
const bpfLoadAttempts = 100

// bpfLoadDeviceProgram loads a cgroup device program into the kernel and
// returns a file descriptor for it.
func bpfLoadDeviceProgram(prog []bpfInsn) (int, error) {
	// kernels before 5.11 charge programs to RLIMIT_MEMLOCK: lift it for the load
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err == nil {
		unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
		defer unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit)
	}

	license := []byte("GPL\x00")

	// The start of union bpf_attr for BPF_PROG_LOAD. Its pointers are 64 bits
	// wide; real pointers, padded on 32-bit systems, keep the memory in place.
	type pad [8 - unsafe.Sizeof(uintptr(0))]byte
	attr := struct {
		ProgType uint32
		InsnCnt  uint32
		Insns    *bpfInsn
		_        pad
		License  *byte
		_        pad
		LogLevel uint32 // no verifier log
		LogSize  uint32
		LogBuf   uint64
	}{
		ProgType: unix.BPF_PROG_TYPE_CGROUP_DEVICE,
		InsnCnt:  uint32(len(prog)),
		Insns:    &prog[0],
		License:  &license[0],
	}

	// a signal, which the Go runtime sends often, stops the verifier with EAGAIN
	var fd uintptr
	var errno unix.Errno
	for i := 0; i < bpfLoadAttempts; i++ {
		fd, _, errno = unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
		if errno != unix.EAGAIN {
			break
		}
	}
	if errno != 0 {
		return -1, fmt.Errorf("load eBPF program: %w", errno)
	}

	return int(fd), nil
}

// cgroupDeviceFilter restricts the devices that the processes in a cgroup v2
// can use to those that rules allow.
func cgroupDeviceFilter(dir string, rules []string) error {
	prog, err := cgroupDeviceProgram(rules)
	if err != nil {
		return err
	}

	fd, err := bpfLoadDeviceProgram(prog)
	if err != nil {
		return err
	}
	// the cgroup keeps the program once attached
	defer unix.Close(fd)

	cgroup, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer cgroup.Close()

	// the start of union bpf_attr for BPF_PROG_ATTACH
	attr := struct {
		TargetFd    uint32
		AttachBpfFd uint32
		AttachType  uint32
		AttachFlags uint32
	}{
		TargetFd:    uint32(cgroup.Fd()),
		AttachBpfFd: uint32(fd),
		AttachType:  unix.BPF_CGROUP_DEVICE,
		// lets a container attach filters of its own to cgroups below this one
		AttachFlags: unix.BPF_F_ALLOW_MULTI,
	}

	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_ATTACH, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return fmt.Errorf("attach eBPF program: %w", errno)
	}

	return nil
}
