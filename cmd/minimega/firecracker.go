// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/sandia-minimega/minimega/v2/internal/bridge"
	"github.com/sandia-minimega/minimega/v2/internal/ron"
	log "github.com/sandia-minimega/minimega/v2/pkg/minilog"
)

const (
	MinVsockCID = 3
	MaxVsockCID = 1<<32 - 2

	// fcSocketTimeout is how long launch waits for the API socket.
	fcSocketTimeout = 10 * time.Second

	// fcVsockUDS is the uds_path of the vsock device in the jail.
	fcVsockUDS = "/v.sock"

	// fcCCPort is the vsock port that miniccc dials for cc, the default
	// -port of miniccc.
	fcCCPort = 9002

	fcTailBytes = 4096
)

// Tests replace these.
var (
	fcCheckHost      = fcCheckHostDefault
	fcPrepareDiskFn  = fcPrepareDisk
	fcReleaseDiskFn  = fcReleaseDisk
	fcApplyInjectsFn = fcApplyInjects
	fcCreateNetns    = bridge.NewNetns
	fcCloseNetns     = (*bridge.Netns).Close
	fcCreateTap      = fcCreateTapDefault
	fcDestroyTap     = fcDestroyTapDefault
	fcJailerCommand  = func(bin string, args []string) *exec.Cmd {
		return exec.Command(bin, args...)
	}
	fcProcDir = "/proc"
)

// fcCCServer is the part of the ron server that Firecracker VMs use. Tests
// replace it.
type fcCCServer interface {
	RegisterVM(ron.VM)
	UnregisterVM(ron.VM)
	ListenUnixBound(path, uuid string, uid int) error
	CloseUnix(path string) error
}

var _ fcCCServer = (*ron.Server)(nil)

// fcLaunchGate limits the number of Firecracker VMs that launch at the same
// time. It is separate from fcLaunchSem, which launches acquire inside it.
var fcLaunchGate fcSemaphore

type FirecrackerConfig struct {
	// Set the Firecracker binary to use. The value is a path on the host or
	// the name of a binary in the host PATH.
	//
	// Note: this configuration only applies to Firecracker-based VMs.
	//
	// Default: "firecracker"
	FirecrackerPath string `config:"firecracker-path" path:"false"`

	// Set the Firecracker jailer binary to use. The value is a path on the
	// host or the name of a binary in the host PATH. The jailer must have the
	// same version as the Firecracker binary.
	//
	// Note: this configuration only applies to Firecracker-based VMs.
	//
	// Default: "jailer"
	JailerPath string `config:"jailer-path" path:"false"`

	// Enable the PCI transport for the devices of a VM. This sets the
	// --enable-pci flag of Firecracker. With the PCI transport, a VM can have
	// up to 31 devices. Without it, the limit is 17 devices. The guest kernel
	// must support PCI.
	//
	// Note: this configuration only applies to Firecracker-based VMs.
	//
	// Default: false
	FirecrackerPCI bool `config:"firecracker-pci"`

	// Add a virtio entropy device to a VM. The guest kernel can use this
	// device as a source of random numbers.
	//
	// Note: this configuration only applies to Firecracker-based VMs.
	//
	// Default: true
	FirecrackerEntropy bool `config:"firecracker-entropy"`

	// Set the guest context ID (CID) of the vsock device of a VM. Each VM has
	// its own vsock device, so all VMs can use the same CID. The value must be
	// in the range 3 to 4294967294.
	//
	// Note: this configuration only applies to Firecracker-based VMs.
	//
	// Default: 3
	VsockCID uint64 `config:"vsock-cid" validate:"validVsockCID"`

	// Set the path prefix of a Firecracker snapshot that vm save wrote. When
	// set, vm launch restores the VM from the snapshot instead of a cold
	// boot.
	//
	// Note: this configuration only applies to Firecracker-based VMs.
	FirecrackerSnapshotPath string `config:"firecracker-snapshot" path:"false"`

	// Files to inject into the first disk at launch, handler is not generated
	// by vmconfiger.
	Injects FCInjects `config:"inject"`
}

type FirecrackerVM struct {
	*BaseVM           // embed
	KVMConfig         // embed; kernel, initrd, append, and disks
	FirecrackerConfig // embed

	// Host objects that the first launch creates and flush removes.
	dirReady  bool
	disks     []fcDisk
	stale     []fcDisk // disks that vm reset-disk could not release
	injected  bool
	kernel    fcCachedFile
	initrd    fcCachedFile
	netns     *bridge.Netns
	mtus      []int
	exportSeq int

	// Objects of the current VMM.
	jail    fcJail
	console *fcConsole
	vmm     *fcProcess
	client  *fcClient
	gen     int // changes at each launch and at flush

	// cc is the ron server from Connect. ccPath is the cc listener of the
	// current jail, or empty.
	cc     fcCCServer
	ccPath string
}

// fcProcess is one jailer process, which execs the VMM in place.
type fcProcess struct {
	cmd    *exec.Cmd
	killed atomic.Bool
	exited chan struct{} // closed when the process exits
	done   chan struct{} // closed after the exit is handled

	state *os.ProcessState
	err   error
}

// fcCachedFile is a cache entry that a VM uses.
type fcCachedFile struct {
	key, path string
}

// Ensure that FirecrackerVM implements the VM interface.
var _ VM = (*FirecrackerVM)(nil)

func (old FirecrackerConfig) Copy() FirecrackerConfig {
	res := old

	if old.Injects != nil {
		res.Injects = make(FCInjects, len(old.Injects))
		copy(res.Injects, old.Injects)
	}

	return res
}

func (vm *FirecrackerConfig) String() string {
	var o bytes.Buffer
	w := new(tabwriter.Writer)
	w.Init(&o, 5, 0, 1, ' ', 0)
	fmt.Fprintln(&o, "Firecracker configuration:")
	fmt.Fprintf(w, "Firecracker Path:\t%v\n", vm.FirecrackerPath)
	fmt.Fprintf(w, "Jailer Path:\t%v\n", vm.JailerPath)
	fmt.Fprintf(w, "PCI:\t%v\n", vm.FirecrackerPCI)
	fmt.Fprintf(w, "Entropy:\t%v\n", vm.FirecrackerEntropy)
	fmt.Fprintf(w, "Vsock CID:\t%v\n", vm.VsockCID)
	fmt.Fprintf(w, "Snapshot:\t%v\n", vm.FirecrackerSnapshotPath)
	fmt.Fprintf(w, "Injects:\t%v\n", vm.Injects)
	w.Flush()
	fmt.Fprintln(&o)
	return o.String()
}

func validVsockCID(_ VMConfig, cid uint64) error {
	if cid < MinVsockCID || cid > MaxVsockCID {
		return fmt.Errorf("vsock-cid must be in range %d-%d", MinVsockCID, MaxVsockCID)
	}

	return nil
}

func NewFirecracker(name, namespace string, config VMConfig) (*FirecrackerVM, error) {
	vm := new(FirecrackerVM)

	var err error
	vm.BaseVM, err = NewBaseVM(name, namespace, config)
	if err != nil {
		return nil, err
	}

	vm.Type = FIRECRACKER

	vm.KVMConfig = config.KVMConfig.Copy()
	vm.FirecrackerConfig = config.FirecrackerConfig.Copy()

	return vm, nil
}

func (vm *FirecrackerVM) Copy() VM {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	vm2 := new(FirecrackerVM)

	// Make shallow copies of all fields.
	*vm2 = *vm

	// Make deep copies.
	vm2.BaseVM = vm.BaseVM.copy()
	vm2.KVMConfig = vm.KVMConfig.Copy()
	vm2.FirecrackerConfig = vm.FirecrackerConfig.Copy()
	vm2.disks = append([]fcDisk(nil), vm.disks...)
	vm2.mtus = append([]int(nil), vm.mtus...)

	return vm2
}

// fcInstanceDir returns the instance directory of VM vmID. <base>/<ID> links
// to it.
func fcInstanceDir(vmID int) string {
	return filepath.Join(fcResolve(*f_firecrackerDir), "vm", strconv.Itoa(vmID))
}

// fcCheckHostDefault checks the binaries, the Firecracker directory, and the
// parent cgroup. It returns the paths of the Firecracker and jailer binaries.
func fcCheckHostDefault(fcPath, jailerPath string) (string, string, error) {
	fc, jailer, err := fcCheckBinaries(fcPath, jailerPath)
	if err != nil {
		return "", "", err
	}

	if p := fcCheckDir(*f_firecrackerDir).Problems(); len(p) > 0 {
		return "", "", fmt.Errorf("firecracker directory: %v", strings.Join(p, "; "))
	}

	if err := fcEnsureParentCgroup(); err != nil {
		return "", "", err
	}

	return fc.Path, jailer.Path, nil
}

func fcCreateTapDefault(nic NetConfig, ns *bridge.Netns, index, uid int) (string, int, error) {
	br, err := getBridge(nic.Bridge)
	if err != nil {
		return "", 0, fmt.Errorf("unable to get bridge %v: %v", nic.Bridge, err)
	}

	return br.CreateNetnsTap(ns, nic.MAC, nic.VLAN, index, uid)
}

func fcDestroyTapDefault(nic NetConfig) error {
	if nic.VLAN == DisconnectedVLAN {
		return bridge.DeleteLink(nic.Tap)
	}

	br, err := getBridge(nic.Bridge)
	if err != nil {
		return err
	}

	return br.DestroyNetnsTap(nic.Tap)
}

// fcCacheBootFile caches a kernel or initrd for VM vmID.
func fcCacheBootFile(src string, vmID int) (fcCachedFile, error) {
	key, path, err := fcCache.get(src, "raw", vmID)
	if err != nil {
		return fcCachedFile{}, err
	}

	// The VMM reads the hard link in the jail as the VM uid.
	if err := os.Chmod(path, 0444); err != nil {
		fcCache.removeUser(key, vmID)
		return fcCachedFile{}, err
	}

	return fcCachedFile{key: key, path: path}, nil
}

func (vm *FirecrackerVM) Launch() error {
	defer vm.lock.Unlock()

	return vm.launch()
}

// launch prepares the VM on first use, then starts and configures a new VMM.
// The VM stays in its state; the caller holds vm.lock.
func (vm *FirecrackerVM) launch() error {
	fcLaunchGate.Acquire()
	defer fcLaunchGate.Release()

	log.Info("launching vm: %v", vm.ID)

	if !vm.dirReady {
		if err := vm.createInstanceDir(); err != nil {
			// The VM needs an instance path to enter ERROR and be flushed.
			if err2 := os.MkdirAll(vm.instancePath, os.FileMode(0700)); err2 != nil {
				vm.State = VM_ERROR
				return fmt.Errorf("unable to create VM dir: %v", err)
			}
			if err2 := vm.createInstancePathAlias(); err2 != nil {
				log.Error("vm %v: createInstancePathAlias: %v", vm.ID, err2)
			}
			return vm.setErrorf("unable to create VM dir: %v", err)
		}

		if err := vm.createInstancePathAlias(); err != nil {
			return vm.setErrorf("createInstancePathAlias: %v", err)
		}

		vm.dirReady = true
	}

	mustWrite(vm.path("name"), vm.Name)

	cfg := VMConfig{BaseConfig: vm.BaseConfig, KVMConfig: vm.KVMConfig, FirecrackerConfig: vm.FirecrackerConfig}

	warnings, err := fcValidateConfig(vm.Name, cfg)
	for _, w := range warnings {
		log.Warn("%v", w)
	}
	if err != nil {
		return vm.setErrorf("%v", err)
	}
	if vm.FirecrackerSnapshotPath != "" {
		return vm.setErrorf("restore from firecracker-snapshot is not supported yet")
	}
	if len(vm.Injects) > 0 && len(vm.Disks) == 0 {
		return vm.setErrorf("vm config inject needs a disk")
	}

	fcBin, jailerBin, err := fcCheckHost(vm.FirecrackerPath, vm.JailerPath)
	if err != nil {
		return vm.setErrorf("%v", err)
	}

	if fcIsBeaconName(vm.Name) {
		log.Info(fcBeaconMessage)
	}

	if err := vm.prepare(); err != nil {
		return vm.setErrorf("%v", err)
	}

	if err := vm.startVMM(cfg, fcBin, jailerBin); err != nil {
		return vm.setErrorf("%v", err)
	}

	return nil
}

// createInstanceDir creates the instance directory and links <base>/<ID> to
// it.
func (vm *FirecrackerVM) createInstanceDir() error {
	dir := fcInstanceDir(vm.ID)
	if err := os.MkdirAll(dir, os.FileMode(0700)); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(vm.instancePath), os.FileMode(0700)); err != nil {
		return err
	}

	return os.Symlink(dir, vm.instancePath)
}

// prepare creates the disks, the boot file cache entries, the netns, and the
// taps that are not there yet. Flush removes them.
func (vm *FirecrackerVM) prepare() error {
	uid := fcVMUID(vm.ID)

	if err := vm.prepareDisks(); err != nil {
		return err
	}

	if vm.kernel.key == "" {
		f, err := fcCacheBootFile(vm.KernelPath, vm.ID)
		if err != nil {
			return fmt.Errorf("unable to cache kernel: %v", err)
		}
		vm.kernel = f
	}

	if vm.InitrdPath != "" && vm.initrd.key == "" {
		f, err := fcCacheBootFile(vm.InitrdPath, vm.ID)
		if err != nil {
			return fmt.Errorf("unable to cache initrd: %v", err)
		}
		vm.initrd = f
	}

	if vm.netns == nil {
		ns, err := fcCreateNetns()
		if err != nil {
			return err
		}
		vm.netns = ns
	}

	if len(vm.mtus) != len(vm.Networks) {
		vm.mtus = make([]int, len(vm.Networks))
	}

	for i := range vm.Networks {
		nic := &vm.Networks[i]
		if nic.Tap != "" {
			continue
		}

		tap, mtu, err := fcCreateTap(*nic, vm.netns, i, uid)
		if err != nil {
			return fmt.Errorf("unable to create tap %v: %v", i, err)
		}

		nic.Tap = tap
		vm.mtus[i] = mtu
	}

	if len(vm.Networks) > 0 {
		if err := vm.writeTaps(); err != nil {
			return fmt.Errorf("unable to write taps: %v", err)
		}
	}

	return nil
}

// prepareDisks creates the disks that are not there yet, and applies the
// injects to disk 0 once.
func (vm *FirecrackerVM) prepareDisks() error {
	dir := fcInstanceDir(vm.ID)
	uid := fcVMUID(vm.ID)

	for i := len(vm.disks); i < len(vm.Disks); i++ {
		d, err := fcPrepareDiskFn(dir, i, vm.Disks[i], vm.Snapshot, vm.ID, uid)
		if err != nil {
			return fmt.Errorf("unable to prepare disk %v: %v", i, err)
		}
		vm.disks = append(vm.disks, d)
	}

	if !vm.injected && vm.Snapshot && len(vm.Injects) > 0 {
		fcLaunchSem.Acquire()
		err := fcApplyInjectsFn(vm.disks[0].HostPath, vm.Injects)
		fcLaunchSem.Release()
		if err != nil {
			return err
		}
		vm.injected = true
	}

	return nil
}

// startVMM builds a new jail, starts the jailer in it, and configures the
// VMM over its API socket.
func (vm *FirecrackerVM) startVMM(cfg VMConfig, fcBin, jailerBin string) error {
	vm.stopVMM()
	vm.stopConsole()
	vm.stopCCListener()

	vm.gen++
	gen := vm.gen

	dir := fcInstanceDir(vm.ID)
	uid := fcVMUID(vm.ID)

	devices, _, _ := fcDeviceCount(cfg)
	bootArgs, rootIndex, err := fcBootArgs(vm.Append, len(vm.disks), devices, vm.FirecrackerPCI)
	if err != nil {
		return err
	}

	j := newFCJail(vm.ID, fcBin)
	vm.jail = j

	if err := fcCheckSocketPath(j.HostPath("/api.sock")); err != nil {
		return err
	}
	if vm.Backchannel {
		if err := fcCheckSocketPath(j.CCSocket()); err != nil {
			return err
		}
	}

	if err := j.Prepare(); err != nil {
		return err
	}

	fail := func(err error) error {
		vm.stopConsole()
		vm.stopCCListener()
		if err2 := j.Destroy(); err2 != nil {
			log.Error("vm %v: remove jail: %v", vm.ID, err2)
		}
		return err
	}

	for i, d := range vm.disks {
		if _, err := j.Link(d.HostPath, fmt.Sprintf("/disk%d", i)); err != nil {
			return fail(err)
		}
	}

	if _, err := j.Link(vm.kernel.path, "/vmlinux"); err != nil {
		return fail(err)
	}
	if vm.initrd.path != "" {
		if _, err := j.Link(vm.initrd.path, "/initrd"); err != nil {
			return fail(err)
		}
	}

	fcLog := filepath.Join(dir, "firecracker.log")
	if err := fcCreateLog(fcLog, uid); err != nil {
		return fail(err)
	}
	if _, err := j.Link(fcLog, "/firecracker.log"); err != nil {
		return fail(err)
	}

	fifo := j.HostPath("/console.fifo")
	if err := fcMakeConsoleFIFO(fifo, uid); err != nil {
		return fail(err)
	}
	if vm.console == nil {
		vm.console = &fcConsole{}
	}
	if err := vm.console.Start(fifo, filepath.Join(dir, "console.log"), fcConsoleMaxBytes); err != nil {
		return fail(fmt.Errorf("unable to start console reader: %v", err))
	}

	if err := vm.startCCListener(j); err != nil {
		return fail(err)
	}

	jailerLog, err := os.OpenFile(filepath.Join(dir, "jailer.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fail(fmt.Errorf("unable to create jailer log: %v", err))
	}

	// The jailer opens the netns through the fd that minimega holds.
	args := fcJailerArgs(j, fcBin, vm.netns.Path(), hostCgroupVersion, vm.FirecrackerPCI)
	log.Debug("vm %v jailer args: %q", vm.ID, args)

	cmd := fcJailerCommand(jailerBin, args)
	cmd.Stdout = jailerLog
	cmd.Stderr = jailerLog

	err = cmd.Start()
	jailerLog.Close()
	if err != nil {
		return fail(fmt.Errorf("unable to start jailer: %v", err))
	}

	vm.Pid = cmd.Process.Pid
	log.Debug("vm %v has pid %v", vm.ID, vm.Pid)

	if err := fcResetOOMScore(vm.Pid); err != nil {
		log.Warn("vm %v: unable to reset oom_score_adj: %v", vm.ID, err)
	}

	p := &fcProcess{
		cmd:    cmd,
		exited: make(chan struct{}),
		done:   make(chan struct{}),
	}
	vm.vmm = p
	vm.waitForExit(p, gen)

	c := newFCClient(j.HostPath("/api.sock"))

	ctx, cancel := context.WithTimeout(context.Background(), fcSocketTimeout)
	go func() {
		select {
		case <-p.exited:
			cancel()
		case <-ctx.Done():
		}
	}()
	err = c.WaitForSocket(ctx)
	cancel()

	if err != nil {
		select {
		case <-p.exited:
			_, msg := vm.classifyExit(p)
			if msg == "" {
				msg = fmt.Sprintf("firecracker exited with %v", p.state)
			}
			return fmt.Errorf("firecracker exited before its API socket was ready: %v", msg)
		default:
		}

		vm.stopVMM()
		return err
	}

	if err := vm.configure(c, bootArgs, rootIndex); err != nil {
		vm.stopVMM()
		return err
	}

	vm.client = c
	vm.waitToKill(p, vm.kill)

	return nil
}

// configure sends the VM configuration to a new VMM.
func (vm *FirecrackerVM) configure(c *fcClient, bootArgs string, rootIndex int) error {
	if err := c.PutLogger("/firecracker.log", "Info"); err != nil {
		return err
	}

	if err := c.PutMachineConfig(int(vm.VCPUs), int(vm.Memory)); err != nil {
		return err
	}

	initrd := ""
	if vm.initrd.path != "" {
		initrd = "/initrd"
	}
	if err := c.PutBootSource("/vmlinux", initrd, bootArgs); err != nil {
		return err
	}

	for i, d := range vm.disks {
		if err := c.PutDrive(fmt.Sprintf("disk%d", i), fmt.Sprintf("/disk%d", i), i == rootIndex, d.ReadOnly, d.CacheType); err != nil {
			return err
		}
	}

	for i, nic := range vm.Networks {
		if err := c.PutNetworkInterface(fmt.Sprintf("eth%d", i), fmt.Sprintf("fc%d", i), nic.MAC, vm.mtus[i]); err != nil {
			return err
		}
	}

	if vm.Backchannel {
		if err := c.PutVsock(uint32(vm.VsockCID), fcVsockUDS); err != nil {
			return err
		}
	}

	if vm.FirecrackerEntropy {
		if err := c.PutEntropy(); err != nil {
			return err
		}
	}

	return c.PutSerial("/console.fifo")
}

// fcCreateLog rotates path to path.1 and creates an empty path that uid owns.
func fcCreateLog(path string, uid int) error {
	if err := os.Rename(path, path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("rotate %v: %v", path, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if err := fcChown(path, uid, uid); err != nil {
		return fmt.Errorf("chown %v: %v", path, err)
	}

	return nil
}

// fcResetOOMScore sets the oom_score_adj of process pid to 0, so that a VMM
// does not keep the score of minimega.
func fcResetOOMScore(pid int) error {
	f, err := os.OpenFile(filepath.Join(fcProcDir, strconv.Itoa(pid), "oom_score_adj"), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}

	if _, err := f.WriteString("0"); err != nil {
		f.Close()
		return err
	}

	return f.Close()
}

// CCSocket returns the host path of the cc listener in the jail. The guest
// dials vsock CID 2, port fcCCPort, and the VMM connects to this socket.
func (j fcJail) CCSocket() string {
	return j.HostPath(fmt.Sprintf("%v_%d", fcVsockUDS, fcCCPort))
}

// startCCListener creates the cc listener in jail j, when the VM has a cc
// server and the jail has no listener yet.
//
// LOCK: Assumes vm.lock is held. ListenUnixBound takes only the ron listener
// lock and never calls back into the VM, so it is safe under vm.lock.
func (vm *FirecrackerVM) startCCListener(j fcJail) error {
	if !vm.Backchannel || vm.cc == nil || vm.ccPath != "" {
		return nil
	}

	p := j.CCSocket()
	if err := vm.cc.ListenUnixBound(p, vm.UUID, j.GID); err != nil {
		return fmt.Errorf("unable to create cc listener: %v", err)
	}
	vm.ccPath = p

	return nil
}

// stopCCListener closes the cc listener of the current jail and the cc
// connections on it.
//
// LOCK: Assumes vm.lock is held. CloseUnix takes only the ron listener and
// accept locks and never calls back into the VM, so it is safe under vm.lock.
func (vm *FirecrackerVM) stopCCListener() {
	if vm.ccPath == "" {
		return
	}

	if err := vm.cc.CloseUnix(vm.ccPath); err != nil {
		log.Error("vm %v: close cc listener: %v", vm.ID, err)
	}
	vm.ccPath = ""
}

// stopVMM kills the current VMM and waits for it to exit. The caller holds
// vm.lock, so the exit handler runs after the caller releases it.
func (vm *FirecrackerVM) stopVMM() {
	p := vm.vmm
	if p == nil {
		return
	}

	select {
	case <-p.exited:
		return
	default:
	}

	p.killed.Store(true)
	if err := p.cmd.Process.Kill(); err != nil {
		log.Debug("vm %v: kill: %v", vm.ID, err)
	}
	<-p.exited
}

func (vm *FirecrackerVM) stopConsole() {
	if vm.console != nil {
		vm.console.Stop()
	}
}

// classifyExit returns the state of the VM after p exited, and an error
// message for VM_ERROR.
func (vm *FirecrackerVM) classifyExit(p *fcProcess) (VMState, string) {
	dir := fcInstanceDir(vm.ID)

	console, _ := fcTail(filepath.Join(dir, "console.log"), fcTailBytes)
	fcLog, _ := fcTail(filepath.Join(dir, "firecracker.log"), fcTailBytes)
	if len(bytes.TrimSpace(fcLog)) == 0 {
		fcLog, _ = fcTail(filepath.Join(dir, "jailer.log"), fcTailBytes)
	}

	return fcClassifyExit(p.state, p.err, p.killed.Load(), console, fcLog)
}

// waitForExit handles the exit of p: it stops the console reader, removes the
// jail, and sets the VM state. It does nothing to the VM when a later launch
// or a flush replaced p.
func (vm *FirecrackerVM) waitForExit(p *fcProcess, gen int) {
	go func() {
		defer close(p.done)

		p.err = p.cmd.Wait()
		p.state = p.cmd.ProcessState
		close(p.exited)

		vm.lock.Lock()
		defer vm.lock.Unlock()

		if vm.gen != gen {
			return
		}

		vm.stopConsole()

		state, msg := vm.classifyExit(p)

		vm.stopCCListener()
		if err := vm.jail.Destroy(); err != nil {
			log.Error("vm %v: remove jail: %v", vm.ID, err)
		}
		vm.client = nil

		if state == VM_ERROR {
			vm.setErrorf("%v", msg)
		} else if vm.State != VM_ERROR {
			vm.setState(VM_QUIT)
		}
	}()
}

// waitToKill kills p when kill closes, and signals vm.cond after the exit is
// handled.
func (vm *FirecrackerVM) waitToKill(p *fcProcess, kill chan bool) {
	go func() {
		defer vm.cond.Signal()

		select {
		case <-p.done:
			log.Info("VM %v exited", vm.ID)
		case <-kill:
			log.Info("Killing VM %v", vm.ID)
			p.killed.Store(true)
			if err := p.cmd.Process.Kill(); err != nil {
				log.Debug("vm %v: kill: %v", vm.ID, err)
			}
			<-p.done
		}
	}()
}

func (vm *FirecrackerVM) Recover(string, int) error {
	defer vm.lock.Unlock()

	return errors.New("recovery is not supported for firecracker VMs")
}

func (vm *FirecrackerVM) Start() error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	switch vm.State {
	case VM_RUNNING:
		return nil
	case VM_PAUSED:
		log.Info("resuming VM: %v", vm.ID)
		if err := vm.client.PatchVMState("Resumed"); err != nil {
			return vm.setErrorf("unable to resume: %v", err)
		}

		vm.setState(VM_RUNNING)
		return nil
	case VM_QUIT, VM_ERROR:
		log.Info("relaunching VM: %v", vm.ID)

		// Create a new channel since we closed the other one to indicate that
		// the VM should quit.
		vm.kill = make(chan bool)

		// launch handles setting the VM to error state
		if err := vm.launch(); err != nil {
			return err
		}
	}

	if vm.client == nil {
		return vm.setErrorf("unable to start: no firecracker VMM")
	}

	log.Info("starting VM: %v", vm.ID)
	if err := vm.client.Action("InstanceStart"); err != nil {
		vm.stopVMM()
		return vm.setErrorf("unable to start: %v", err)
	}

	vm.setState(VM_RUNNING)

	return nil
}

func (vm *FirecrackerVM) Stop() error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	if vm.State != VM_RUNNING {
		return vmNotRunning(vm.Name)
	}

	log.Info("stopping VM: %v", vm.ID)
	if err := vm.client.PatchVMState("Paused"); err != nil {
		return vm.setErrorf("unable to pause: %v", err)
	}

	vm.setState(VM_PAUSED)

	return nil
}

// Flush removes the jail, the disks, the taps, the netns, and the instance
// directory. It logs errors and continues.
func (vm *FirecrackerVM) Flush() error {
	vm.lock.Lock()
	defer vm.lock.Unlock()

	vm.gen++
	vm.stopVMM()
	vm.stopConsole()
	vm.stopCCListener()
	vm.client = nil

	if vm.jail.ID != "" {
		if err := vm.jail.Destroy(); err != nil {
			log.Error("vm %v: remove jail: %v", vm.ID, err)
		}
	}

	for i, d := range append(vm.disks, vm.stale...) {
		if err := fcReleaseDiskFn(d); err != nil {
			log.Error("vm %v: release disk %v: %v", vm.ID, i, err)
		}
	}
	vm.disks, vm.stale = nil, nil

	for _, f := range []fcCachedFile{vm.kernel, vm.initrd} {
		if f.key != "" {
			fcCache.removeUser(f.key, vm.ID)
		}
	}
	vm.kernel, vm.initrd = fcCachedFile{}, fcCachedFile{}

	for _, nic := range vm.Networks {
		if nic.Tap == "" {
			continue
		}

		if err := fcDestroyTap(nic); err != nil {
			log.Error("leaked tap %v: %v", nic.Tap, err)
		}
	}

	if vm.netns != nil {
		if err := fcCloseNetns(vm.netns); err != nil {
			log.Error("vm %v: close netns: %v", vm.ID, err)
		}
		vm.netns = nil
	}

	// A failed launch can leave the directory with dirReady false.
	if err := os.RemoveAll(fcInstanceDir(vm.ID)); err != nil {
		log.Error("vm %v: remove instance directory: %v", vm.ID, err)
	}
	vm.dirReady = false

	fcExports.remove(vm.ID)

	return vm.BaseVM.Flush()
}

func (vm *FirecrackerVM) String() string {
	return fmt.Sprintf("%s:%d:firecracker", hostname, vm.ID)
}

func (vm *FirecrackerVM) Info(field string) (string, error) {
	// Let BaseVM answer generic fields first.
	if v, err := vm.BaseVM.Info(field); err == nil {
		return v, nil
	}

	vm.lock.Lock()
	defer vm.lock.Unlock()

	if field == "console" {
		return vm.path("console.log"), nil
	}

	if v, err := vm.FirecrackerConfig.Info(field); err == nil {
		return v, nil
	}

	return vm.KVMConfig.Info(field)
}

func (vm *FirecrackerVM) Conflicts(vm2 VM) error {
	switch vm2 := vm2.(type) {
	case *FirecrackerVM:
		return vm.BaseVM.conflicts(vm2.BaseVM)
	case *KvmVM:
		return vm.BaseVM.conflicts(vm2.BaseVM)
	case *ContainerVM:
		return vm.BaseVM.conflicts(vm2.BaseVM)
	case *AndroidVM:
		return vm.BaseVM.conflicts(vm2.BaseVM)
	}

	return errors.New("unknown VM type")
}

func (vm *FirecrackerVM) Screenshot(size int) ([]byte, error) {
	return nil, errors.New("screenshots are not supported for firecracker VMs")
}

func (vm *FirecrackerVM) Connect(cc *ron.Server, reconnect bool) error {
	return vm.connectCC(cc)
}

func (vm *FirecrackerVM) Disconnect(cc *ron.Server) error {
	return vm.disconnectCC(cc)
}

// connectCC registers the VM with cc once, and creates the cc listener when a
// VMM runs without one. A relaunch creates the listener before boot, but the
// first boot gets it here: the namespace calls Connect after the first Start.
func (vm *FirecrackerVM) connectCC(cc fcCCServer) error {
	if !vm.Backchannel {
		return nil
	}

	vm.lock.Lock()
	known := vm.cc == cc
	vm.lock.Unlock()

	// RegisterVM takes the ron client lock, which comes before vm.lock.
	if !known {
		cc.RegisterVM(vm)
	}

	vm.lock.Lock()
	defer vm.lock.Unlock()

	vm.cc = cc
	if vm.client == nil {
		return nil
	}

	return vm.startCCListener(vm.jail)
}

// disconnectCC closes the cc listener and unregisters the VM from cc.
func (vm *FirecrackerVM) disconnectCC(cc fcCCServer) error {
	if !vm.Backchannel {
		return nil
	}

	vm.lock.Lock()
	vm.stopCCListener()
	vm.cc = nil
	vm.lock.Unlock()

	cc.UnregisterVM(vm)

	return nil
}

func (vm *FirecrackerVM) ProcStats() (map[int]*ProcStats, error) {
	if vm.Pid <= 0 {
		return nil, errors.New("firecracker VM has no PID")
	}

	p, err := GetProcStats(vm.Pid)
	if err != nil {
		return nil, err
	}

	return map[int]*ProcStats{vm.Pid: p}, nil
}

func (vm *FirecrackerVM) WriteConfig(w io.Writer) error {
	if err := vm.BaseConfig.WriteConfig(w); err != nil {
		return err
	}

	if err := vm.KVMConfig.WriteConfig(w); err != nil {
		return err
	}

	return vm.FirecrackerConfig.WriteConfig(w)
}
