// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package main

import (
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sandia-minimega/minimega/v2/pkg/minicli"
)

// blockingVM is a VM whose Launch waits until release is closed.
type blockingVM struct {
	*FirecrackerVM
	release <-chan struct{}
}

func (vm *blockingVM) Launch() error {
	defer vm.lock.Unlock()

	<-vm.release

	return os.MkdirAll(vm.instancePath, 0700)
}

func (vm *blockingVM) Conflicts(vm2 VM) error {
	if vm2, ok := vm2.(*blockingVM); ok {
		return vm.BaseVM.conflicts(vm2.BaseVM)
	}

	return errors.New("unknown VM type")
}

func testLaunchVMs(t *testing.T, release <-chan struct{}) *VMs {
	t.Helper()

	oldBase, oldNewVM := *f_base, newVM
	t.Cleanup(func() { *f_base, newVM = oldBase, oldNewVM })

	*f_base = t.TempDir()
	newVM = func(name, namespace string, _ VMType, config VMConfig) (VM, error) {
		fc, err := NewFirecracker(name, namespace, config)
		if err != nil {
			return nil, err
		}

		return &blockingVM{FirecrackerVM: fc, release: release}, nil
	}

	return &VMs{m: map[int]VM{}}
}

func testLaunchQueue(names ...string) *QueuedVMs {
	return &QueuedVMs{Names: names, VMType: FIRECRACKER, VMConfig: NewVMConfig()}
}

func launchInfoNames(vms *VMs) []string {
	resp := &minicli.Response{}
	vms.Info([]string{"name"}, resp)

	names := []string{}
	for _, row := range resp.Tabular {
		names = append(names, row[0])
	}
	sort.Strings(names)

	return names
}

func waitLaunchCount(t *testing.T, vms *VMs, want int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for vms.Count() != want {
		if time.Now().After(deadline) {
			t.Fatalf("Count() = %v, want %v", vms.Count(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func drainLaunchErrs(errs <-chan error) []error {
	var res []error
	for err := range errs {
		res = append(res, err)
	}

	return res
}

func TestVMsLaunchDoesNotBlockInfo(t *testing.T) {
	release := make(chan struct{})
	vms := testLaunchVMs(t, release)

	errs := vms.Launch("", DefaultNamespace, testLaunchQueue("slow"))
	waitLaunchCount(t, vms, 1)

	done := make(chan []string)
	go func() { done <- launchInfoNames(vms) }()

	select {
	case names := <-done:
		if len(names) != 0 {
			t.Errorf("Info() during launch = %v, want no VMs", names)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("Info() blocked while a VM is launching")
	}

	close(release)

	if got := drainLaunchErrs(errs); len(got) != 0 {
		t.Fatalf("Launch() errors = %v", got)
	}

	if got, want := launchInfoNames(vms), []string{"slow"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Info() after launch = %v, want %v", got, want)
	}
	if got := vms.Count(); got != 1 {
		t.Errorf("Count() after launch = %v, want 1", got)
	}
}

func TestVMsLaunchConflictInBatch(t *testing.T) {
	release := make(chan struct{})
	close(release)
	vms := testLaunchVMs(t, release)

	got := drainLaunchErrs(vms.Launch("", DefaultNamespace, testLaunchQueue("dup", "dup")))
	if len(got) != 1 || !strings.Contains(got[0].Error(), "duplicate VM name") {
		t.Fatalf("Launch() errors = %v, want one duplicate VM name error", got)
	}

	if got, want := launchInfoNames(vms), []string{"dup"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Info() = %v, want %v", got, want)
	}
}

func TestVMsLaunchConflictWithPending(t *testing.T) {
	release := make(chan struct{})
	vms := testLaunchVMs(t, release)

	first := vms.Launch("", DefaultNamespace, testLaunchQueue("a"))
	waitLaunchCount(t, vms, 1)

	got := drainLaunchErrs(vms.Launch("", DefaultNamespace, testLaunchQueue("a")))
	if len(got) != 1 || !strings.Contains(got[0].Error(), "duplicate VM name") {
		close(release)
		t.Fatalf("second Launch() errors = %v, want one duplicate VM name error", got)
	}

	close(release)

	if got := drainLaunchErrs(first); len(got) != 0 {
		t.Fatalf("first Launch() errors = %v", got)
	}
	if got, want := launchInfoNames(vms), []string{"a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Info() = %v, want %v", got, want)
	}
}

func TestVMsFlushAllWaitsForLaunches(t *testing.T) {
	release := make(chan struct{})
	vms := testLaunchVMs(t, release)

	errs := vms.Launch("", DefaultNamespace, testLaunchQueue("slow"))
	waitLaunchCount(t, vms, 1)

	done := make(chan struct{})
	go func() {
		vms.FlushAll(nil)
		close(done)
	}()

	select {
	case <-done:
		close(release)
		t.Fatal("FlushAll() returned while a VM is launching")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("FlushAll() did not return after the launch")
	}

	if got := drainLaunchErrs(errs); len(got) != 0 {
		t.Fatalf("Launch() errors = %v", got)
	}
	if got, want := launchInfoNames(vms), []string{"slow"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Info() = %v, want %v", got, want)
	}
}
