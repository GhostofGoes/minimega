// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package main

import (
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sandia-minimega/minimega/v2/internal/minitunnel"
	"github.com/sandia-minimega/minimega/v2/internal/ron"
	"github.com/sandia-minimega/minimega/v2/pkg/minicli"
)

func TestCCRTunnelDoesNotRequireVM(t *testing.T) {
	ccServer, err := ron.NewServer(t.TempDir(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ccServer.Destroy()

	c, err := minicli.Compile("cc rtunnel 4444 localhost 80")
	if err != nil {
		t.Fatal(err)
	}

	if !c.BoolArgs["rtunnel"] {
		t.Fatalf("rtunnel not set: %v", c.BoolArgs)
	}
	for k, want := range map[string]string{"src": "4444", "host": "localhost", "dst": "80"} {
		if got := c.StringArgs[k]; got != want {
			t.Errorf("StringArgs[%q] = %q, want %q", k, got, want)
		}
	}

	// with no clients connected, rtunnel reports that instead of a missing VM
	ns := &Namespace{Name: "test", ccServer: ccServer}
	err = cliCC(ns, c, &minicli.Response{})
	if err == nil || err.Error() != "no clients connected" {
		t.Fatalf("cc rtunnel = %v, want no clients connected", err)
	}
}

func TestCCRTunnelUsesNamespaceFilter(t *testing.T) {
	ccServer, err := ron.NewServer(t.TempDir(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ccServer.UseVMs = false
	t.Cleanup(func() {
		waitFor(t, "clients to disconnect", func() bool { return ccServer.Clients() == 0 })
		ccServer.Destroy()
	})

	path := filepath.Join(t.TempDir(), "cc")
	if err := ccServer.ListenUnix(path); err != nil {
		t.Fatal(err)
	}

	// the windows client never starts its tunnel, so rtunnel fails if it
	// does not apply the filter
	dialCCClient(t, path, &ron.Client{UUID: "linux-client", OS: "linux"}, true)
	dialCCClient(t, path, &ron.Client{UUID: "windows-client", OS: "windows"}, false)

	waitFor(t, "windows-client to connect", func() bool { return ccServer.HasClient("windows-client") })
	waitFor(t, "linux-client tunnel", func() bool {
		_, err := ccServer.ListForwards("linux-client")
		return err == nil
	})

	ns := &Namespace{Name: "test", ccServer: ccServer}

	rtunnel := func(src int, host string, dst int) error {
		c, err := minicli.Compile(fmt.Sprintf("cc rtunnel %d %s %d", src, host, dst))
		if err != nil {
			t.Fatal(err)
		}

		return cliCC(ns, c, &minicli.Response{})
	}

	ns.ccFilter = &ron.Filter{OS: "plan9"}
	if err := rtunnel(freeTCPPort(t), "127.0.0.1", 80); err == nil || err.Error() != "no clients match filter: os=plan9" {
		t.Fatalf("cc rtunnel with os=plan9 = %v, want no clients match filter", err)
	}

	dest, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	served := make(chan error, 1)
	go func() {
		conn, err := dest.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, len("hello"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			served <- err
			return
		}
		if string(buf) != "hello" {
			served <- fmt.Errorf("destination got %q, want %q", buf, "hello")
			return
		}

		_, err = conn.Write([]byte("world"))
		served <- err
	}()

	ns.ccFilter = &ron.Filter{OS: "linux"}
	src := freeTCPPort(t)
	if err := rtunnel(src, "127.0.0.1", dest.Addr().(*net.TCPAddr).Port); err != nil {
		t.Fatalf("cc rtunnel with os=linux: %v", err)
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", src))
	if err != nil {
		t.Fatalf("dial reverse tunnel: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len("world"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "world" {
		t.Fatalf("client got %q, want %q", buf, "world")
	}

	if err := <-served; err != nil {
		t.Fatal(err)
	}
}

func TestCCRTunnelListPatterns(t *testing.T) {
	if err := minicli.Validate(); err != nil {
		t.Fatal(err)
	}

	for input, vm := range map[string]string{
		"cc rtunnel list":           "",
		"cc rtunnel list all":       "all",
		"cc rtunnel list server-vm": "server-vm",
	} {
		c, err := minicli.Compile(input)
		if err != nil {
			t.Fatalf("Compile(%q): %v", input, err)
		}

		if !c.BoolArgs["rtunnel"] || !c.BoolArgs["list"] {
			t.Errorf("%q: BoolArgs = %v, want rtunnel and list", input, c.BoolArgs)
		}
		if got := c.StringArgs["vm"]; got != vm {
			t.Errorf("%q: StringArgs[vm] = %q, want %q", input, got, vm)
		}
		if _, ok := c.StringArgs["src"]; ok {
			t.Errorf("%q: StringArgs = %v, want no src", input, c.StringArgs)
		}
	}

	c, err := minicli.Compile("cc rtunnel 4444 list 80")
	if err != nil {
		t.Fatal(err)
	}
	if c.BoolArgs["list"] || c.StringArgs["host"] != "list" {
		t.Fatalf("cc rtunnel 4444 list 80: BoolArgs = %v, StringArgs = %v, want host list", c.BoolArgs, c.StringArgs)
	}
}

func TestCCRTunnelList(t *testing.T) {
	ccServer, err := ron.NewServer(t.TempDir(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ccServer.UseVMs = false
	t.Cleanup(func() {
		waitFor(t, "clients to disconnect", func() bool { return ccServer.Clients() == 0 })
		ccServer.Destroy()
	})

	path := filepath.Join(t.TempDir(), "cc")
	if err := ccServer.ListenUnix(path); err != nil {
		t.Fatal(err)
	}

	// the windows client never starts its tunnel, so it has no reverse tunnels
	linux := dialCCClient(t, path, &ron.Client{UUID: "linux-client", OS: "linux"}, true)
	dialCCClient(t, path, &ron.Client{UUID: "windows-client", OS: "windows"}, false)

	waitFor(t, "windows-client to connect", func() bool { return ccServer.HasClient("windows-client") })
	waitFor(t, "linux-client tunnel", func() bool {
		_, err := ccServer.ListForwards("linux-client")
		return err == nil
	})

	ns := &Namespace{
		Name:     "test",
		ccServer: ccServer,
		VMs: VMs{m: map[int]VM{
			1: &KvmVM{BaseVM: &BaseVM{ID: 1, Name: "linux-vm", BaseConfig: BaseConfig{UUID: "linux-client"}}},
			2: &KvmVM{BaseVM: &BaseVM{ID: 2, Name: "windows-vm", BaseConfig: BaseConfig{UUID: "windows-client"}}},
		}},
	}

	run := func(input string) (*minicli.Response, error) {
		c, err := minicli.Compile(input)
		if err != nil {
			t.Fatal(err)
		}

		resp := &minicli.Response{}
		return resp, cliCC(ns, c, resp)
	}

	header := []string{"vm", "src port", "dst", "dst port"}

	resp, err := run("cc rtunnel list")
	if err != nil {
		t.Fatalf("cc rtunnel list: %v", err)
	}
	if !reflect.DeepEqual(resp.Header, header) || len(resp.Tabular) != 0 {
		t.Fatalf("cc rtunnel list before rtunnel = %v %v, want header %v and no rows", resp.Header, resp.Tabular, header)
	}

	lo, hi := freeTCPPort(t), freeTCPPort(t)
	for hi == lo {
		hi = freeTCPPort(t)
	}
	if hi < lo {
		lo, hi = hi, lo
	}

	// windows-client fails without its tunnel, but linux-client opens one
	if _, err := run(fmt.Sprintf("cc rtunnel %d 127.0.0.1 80", hi)); err == nil || err.Error() != "windows-client: tunnel has not been initialized" {
		t.Fatalf("cc rtunnel without filter = %v, want an error for windows-client", err)
	}

	ns.ccFilter = &ron.Filter{OS: "linux"}
	if _, err := run(fmt.Sprintf("cc rtunnel %d localhost 8080", lo)); err != nil {
		t.Fatalf("cc rtunnel with os=linux: %v", err)
	}

	want := [][]string{
		{"linux-vm", strconv.Itoa(lo), "localhost", "8080"},
		{"linux-vm", strconv.Itoa(hi), "127.0.0.1", "80"},
	}

	for _, input := range []string{"cc rtunnel list", "cc rtunnel list all", "cc rtunnel list linux-vm"} {
		resp, err := run(input)
		if err != nil {
			t.Fatalf("%v: %v", input, err)
		}
		if !reflect.DeepEqual(resp.Header, header) || !reflect.DeepEqual(resp.Tabular, want) {
			t.Errorf("%v = %v %v, want %v %v", input, resp.Header, resp.Tabular, header, want)
		}
	}

	resp, err = run("cc rtunnel list windows-vm")
	if err != nil || len(resp.Tabular) != 0 {
		t.Fatalf("cc rtunnel list windows-vm = %v, %v, want no rows", resp.Tabular, err)
	}

	if _, err := run("cc rtunnel list missing-vm"); err == nil || !isVMNotFound(err.Error()) {
		t.Fatalf("cc rtunnel list missing-vm = %v, want vm not found", err)
	}

	linux.Close()
	waitFor(t, "linux-client to disconnect", func() bool { return !ccServer.HasClient("linux-client") })

	resp, err = run("cc rtunnel list")
	if err != nil || len(resp.Tabular) != 0 {
		t.Fatalf("cc rtunnel list after disconnect = %v, %v, want no rows", resp.Tabular, err)
	}

	if _, err := run("cc rtunnel list linux-vm"); err == nil || err.Error() != "no such client: linux-client" {
		t.Fatalf("cc rtunnel list linux-vm after disconnect = %v, want no such client", err)
	}
}

// dialCCClient connects to the cc server at path as client. When tunnel is
// true, it also serves minitunnel traffic the same way miniccc does. Close the
// returned connection to disconnect the client.
func dialCCClient(t *testing.T, path string, client *ron.Client, tunnel bool) net.Conn {
	t.Helper()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}

	local, remote := net.Pipe()
	t.Cleanup(func() {
		conn.Close()
		local.Close()
		remote.Close()
	})

	if _, err := io.WriteString(conn, "RON"); err != nil {
		t.Fatal(err)
	}
	magic := make([]byte, len("RON"))
	if _, err := io.ReadFull(conn, magic); err != nil {
		t.Fatal(err)
	}

	enc, dec := gob.NewEncoder(conn), gob.NewDecoder(conn)

	hello := &ron.Message{Type: ron.MESSAGE_CLIENT, UUID: client.UUID, Version: "v1", Client: client}
	if err := enc.Encode(hello); err != nil {
		t.Fatal(err)
	}

	var ack ron.Message
	if err := dec.Decode(&ack); err != nil {
		t.Fatal(err)
	}

	var encLock sync.Mutex
	send := func(m *ron.Message) error {
		encLock.Lock()
		defer encLock.Unlock()

		return enc.Encode(m)
	}

	if tunnel {
		go minitunnel.ListenAndServe(local)
		go ron.Trunk(remote, client.UUID, send)
	}

	go func() {
		for {
			var m ron.Message
			if err := dec.Decode(&m); err != nil {
				return
			}
			if tunnel && m.Type == ron.MESSAGE_TUNNEL {
				if _, err := remote.Write(m.Tunnel); err != nil {
					return
				}
			}
		}
	}()

	return conn
}

func freeTCPPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	return ln.Addr().(*net.TCPAddr).Port
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %v", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMergeCCRTunnelResponses(t *testing.T) {
	ok := &minicli.Response{Host: "a"}
	noMatch := &minicli.Response{Host: "b", Error: "no clients match filter: os=linux"}
	noConn := &minicli.Response{Host: "c", Error: "no clients connected"}
	failed := &minicli.Response{Host: "d", Error: "client uuid-1: timeout"}

	for _, tc := range []struct {
		name string
		in   minicli.Responses
		want minicli.Responses
	}{
		{"success and no match", minicli.Responses{ok, noMatch}, minicli.Responses{ok}},
		{"all no match", minicli.Responses{noMatch, noConn}, minicli.Responses{noMatch}},
		{"failure and no match", minicli.Responses{noConn, failed}, minicli.Responses{failed}},
		{"success and failure", minicli.Responses{ok, failed}, minicli.Responses{ok, failed}},
	} {
		if got := mergeCCRTunnelResponses(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v: mergeCCRTunnelResponses = %v, want %v", tc.name, got, tc.want)
		}
	}
}
