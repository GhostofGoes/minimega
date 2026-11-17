// Copyright (2012) Sandia Corporation.
// Under the terms of Contract DE-AC04-94AL85000 with Sandia Corporation,
// the U.S. Government retains certain rights in this software.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/sandia-minimega/minimega/v2/internal/bridge"
	"github.com/sandia-minimega/minimega/v2/internal/vlans"
	"github.com/sandia-minimega/minimega/v2/pkg/minicli"
	log "github.com/sandia-minimega/minimega/v2/pkg/minilog"
)

const (
	DisconnectedVLAN = -1
)

const (
	DefaultBridge = "mega_bridge"
	TapFmt        = "mega_tap%v"
	BondFmt       = "mega_bond%v"
	TapReapRate   = time.Second
)

type Tap struct {
	lan  int
	host bool
}

var bridges = bridge.NewBridges(DefaultBridge, TapFmt, BondFmt)

// reapTaps removes the defunct taps on all bridges now. It logs an error because
// the work that marked the taps is already done and the periodic reaper retries.
func reapTaps() {
	if err := bridges.ReapTaps(); err != nil {
		log.Error("reaping taps: %v", err)
	}
}

// tapReaperStart periodically calls bridges.ReapTaps
func tapReaperStart() {
	go func() {
		for {
			time.Sleep(TapReapRate)
			log.Debugln("periodic reapTaps")
			if err := bridges.ReapTaps(); err != nil {
				log.Errorln(err)
			}
		}
	}()
}

// destroy all bridges
func bridgesDestroy() error {
	if err := bridges.Destroy(); err != nil {
		return err
	}

	// Clean up bridges file
	return bridgesFile.reset(func() error {
		bridgeFile := filepath.Join(*f_base, "bridges")
		if err := os.Remove(bridgeFile); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("could not remove bridge file: %v", err)
		}
		return nil
	})
}

// bridgeFileDelay is the maximum time that a change other than a new bridge
// waits before bridgeFileWriter writes it.
const bridgeFileDelay = time.Second

// bridgeFileWriter writes the bridges state file, which nuke reads to find the
// bridges to delete. It writes the file at once for a bridge that the last
// write did not include. It writes other changes, such as VLANs, at most once
// each delay.
type bridgeFileWriter struct {
	mu    sync.Mutex
	delay time.Duration
	// write writes the file and returns the names of the bridges in it.
	write   func() map[string]bool
	names   map[string]bool
	pending bool
}

var bridgesFile = &bridgeFileWriter{
	delay: bridgeFileDelay,
	write: func() map[string]bool {
		info := bridges.Info()
		mustWrite(filepath.Join(*f_base, "bridges"), formatBridgeInfo(info))

		names := map[string]bool{}
		for _, i := range info {
			names[i.Name] = true
		}
		return names
	},
}

// update records a use of bridge name.
func (w *bridgeFileWriter) update(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.names[name] {
		w.pending = false
		w.names = w.write()
		return
	}

	if !w.pending {
		w.pending = true
		time.AfterFunc(w.delay, w.flush)
	}
}

func (w *bridgeFileWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.pending {
		w.pending = false
		w.names = w.write()
	}
}

// reset cancels a pending write, forgets the bridges, and runs fn.
func (w *bridgeFileWriter) reset(fn func() error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.pending = false
	w.names = nil

	return fn()
}

// getBridge is a wrapper for `bridges.Get` that gets the bridge and then
// updates the bridges state file on disk.
func getBridge(b string) (*bridge.Bridge, error) {
	br, err := bridges.Get(b)
	if err != nil {
		return nil, err
	}

	bridgesFile.update(br.Name)

	return br, nil
}

// formatBridgeInfo returns formatted information about the bridges in info.
func formatBridgeInfo(info []bridge.BridgeInfo) string {
	if len(info) == 0 {
		return ""
	}

	var o bytes.Buffer
	w := new(tabwriter.Writer)
	w.Init(&o, 5, 0, 1, ' ', 0)
	fmt.Fprintf(w, "Bridge\tExisted before minimega\tActive VLANS\n")
	for _, i := range info {
		fmt.Fprintf(w, "%v\t%v\t%v\n", i.Name, i.PreExist, i.VLANs)
	}

	w.Flush()
	return o.String()
}

// hostTapCreate creates a host tap based on the supplied arguments.
func hostTapCreate(b, tap string, v int) (string, error) {
	if b == "" {
		b = DefaultBridge
	}

	if isReserved(b) {
		return "", fmt.Errorf("`%s` is a reserved word -- cannot use for bridge name", b)
	}

	if isReserved(tap) {
		return "", fmt.Errorf("`%s` is a reserved word -- cannot use for tap name", tap)
	}

	br, err := getBridge(b)
	if err != nil {
		return "", err
	}

	tap, err = br.CreateHostTap(tap, v)
	if err == nil {
		mustWrite(filepath.Join(*f_base, "taps"), hostTapInfo())
	}

	return tap, err
}

// hostTapList populates resp with information about all the host taps.
func hostTapList(ns *Namespace, resp *minicli.Response) {
	resp.Header = []string{"bridge", "tap", "vlan"}
	resp.Tabular = [][]string{}

	// find all the host taps first
	for _, tap := range bridges.HostTaps() {
		if !ns.Taps[tap.Name] {
			continue
		}

		row := []string{
			tap.Bridge, tap.Name, printVLAN(ns.Name, tap.VLAN),
		}

		resp.Tabular = append(resp.Tabular, row)
	}
}

// hostTapDelete deletes a host tap by name or all host taps if Wildcard is
// specified.
func hostTapDelete(ns *Namespace, s string) error {
	// helper to find and delete a tap t
	delTap := func(t string) error {
		tap, err := bridges.FindTap(t)
		if err != nil {
			return err
		} else if !tap.Host {
			return errors.New("not a host tap")
		} else if !ns.Taps[tap.Name] {
			return errors.New("not a host tap in active namespace")
		}

		br, err := getBridge(tap.Bridge)
		if err != nil {
			return err
		}

		if err := br.DestroyTap(tap.Name); err != nil {
			return err
		}

		// update the host taps for the namespace
		delete(ns.Taps, tap.Name)
		return nil
	}

	var err error

	if s == Wildcard {
		for tap := range ns.Taps {
			if err = delTap(tap); err != nil {
				break
			}
		}
	} else if err = delTap(s); err == nil {
		mustWrite(filepath.Join(*f_base, "taps"), hostTapInfo())
	}

	// remove the deleted taps before the command returns
	reapTaps()

	return err
}

func recoverHostTaps() error {
	f, err := os.Open(filepath.Join(*f_base, "taps"))
	if err == nil {
		var (
			scanner = bufio.NewScanner(f)
			skip    = true
		)

		for scanner.Scan() {
			if skip {
				// skip first line in file (header data)
				skip = false
				continue
			}

			fields := strings.Fields(scanner.Text())

			if len(fields) != 3 {
				return fmt.Errorf("expected exactly three columns in taps file: got %d", len(fields))
			}

			var (
				bridge = fields[0]
				tap    = fields[1]
				alias  = fields[2]
			)

			br, err := bridges.Get(bridge)
			if err != nil {
				return fmt.Errorf("unable to get bridge %s for host tap %s: %w", bridge, tap, err)
			}

			vlan, err := vlans.GetVLAN("", alias)
			if err != nil {
				return fmt.Errorf("unable to get VLAN ID for alias %s on host tap %s: %w", alias, tap, err)
			}

			br.RecoverTap(tap, "", vlan, true)
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("unable to process taps file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unable to open taps file: %w", err)
	}

	return nil
}

// hostTapInfo returns formatted information about all the host taps.
func hostTapInfo() string {
	taps := bridges.HostTaps()
	if len(taps) == 0 {
		return ""
	}

	var o bytes.Buffer

	w := new(tabwriter.Writer)
	w.Init(&o, 5, 0, 1, ' ', 0)

	fmt.Fprintf(w, "Bridge\tTap\tVLAN\n")

	for _, t := range taps {
		alias := strings.Fields(vlans.PrintVLAN("", t.VLAN))[0]
		fmt.Fprintf(w, "%v\t%v\t%v\n", t.Bridge, t.Name, alias)
	}

	w.Flush()
	return o.String()
}

func mirrorDelete(ns *Namespace, name string) error {
	delMirror := func(m string) error {
		if !ns.Mirrors[m] {
			return errors.New("not a valid mirror")
		}

		tap, err := bridges.FindTap(m)
		if err != nil {
			return err
		}

		br, err := getBridge(tap.Bridge)
		if err != nil {
			return err
		}

		if err := br.DestroyMirror(m); err != nil {
			return err
		}

		// update the mirrors for the namespace
		delete(ns.Mirrors, m)
		return nil
	}

	if name == Wildcard || name == "" {
		for mirror := range ns.Mirrors {
			if err := delMirror(mirror); err != nil {
				return err
			}
		}

		return nil
	}

	return delMirror(name)
}

// mirrorDeleteVM looks up the name of the interface(s) for the VM and then
// calls mirrorDelete on them.
func mirrorDeleteVM(ns *Namespace, svm, si string) error {
	vm := ns.FindVM(svm)
	if vm == nil {
		return vmNotFound(svm)
	}

	// delete all mirrors for all interfaces
	if si == Wildcard {
		networks := vm.GetNetworks()

		for _, nic := range networks {
			if !ns.Mirrors[nic.Tap] {
				continue
			}

			if err := mirrorDelete(ns, nic.Tap); err != nil {
				return err
			}
		}

		return nil
	}

	i, err := strconv.Atoi(si)
	if err != nil {
		return fmt.Errorf("invalid interface number: `%v`", si)
	}

	nic, err := vm.GetNetwork(i)
	if err != nil {
		return err
	}

	return mirrorDelete(ns, nic.Tap)
}
