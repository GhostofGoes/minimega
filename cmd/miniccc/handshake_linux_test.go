// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/gob"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sandia-minimega/minimega/v2/internal/ron"
)

const (
	testUUIDA = "a5ba6920-5bcf-4022-b8cf-015425f7b05c"
	testUUIDB = "3b440429-067f-5b75-a0c3-f436519f8ccb"
)

var testClientOnce sync.Once

// newTestClient sets up the client as NewClient does, with claim as the UUID
// that it claims. It makes the client channels only once, because the command
// handler of an earlier client loop can still read them.
func newTestClient(claim string) {
	testClientOnce.Do(func() {
		// NewClient does not read the guest UUID when -uuid is set
		uuid := *f_uuid
		*f_uuid = testUUIDA
		NewClient()
		*f_uuid = uuid
	})

	client.Lock()
	defer client.Unlock()

	client.claim = claim
	client.UUID = claim
	client.acked = false
}

// saveClientFlags restores the dial flags when the test ends.
func saveClientFlags(t *testing.T) {
	family, parent, serial, uuid := *f_family, *f_parent, *f_serial, *f_uuid
	t.Cleanup(func() {
		*f_family, *f_parent, *f_serial, *f_uuid = family, parent, serial, uuid
	})
}

// resetClientState clears the client identity and connection.
func resetClientState() {
	client.Lock()
	defer client.Unlock()

	client.UUID, client.claim, client.acked = "", "", false
	client.conn, client.enc, client.dec = nil, nil, nil
}

// TestHandshakeClaim checks the UUID that each handshake claims when the host
// binds the first connection to testUUIDA and the second to testUUIDB. A
// client without a claim takes the UUID that the host sets.
func TestHandshakeClaim(t *testing.T) {
	saveClientFlags(t)
	defer resetClientState()

	const own = "6f1b6a3e-2f5c-4d1e-9a7b-0c8d9e0f1a2b"

	for _, tt := range []struct {
		name   string
		claim  string
		claims [2]string
		final  string
	}{
		{"own UUID", own, [2]string{own, own}, own},
		{"no UUID", "", [2]string{"", ""}, testUUIDB},
	} {
		t.Run(tt.name, func(t *testing.T) {
			newTestClient(tt.claim)

			var buf bytes.Buffer
			send := func() string {
				buf.Reset()
				client.Lock()
				client.enc = gob.NewEncoder(&buf)
				client.Unlock()

				heartbeat()

				var m ron.Message
				if err := gob.NewDecoder(&buf).Decode(&m); err != nil {
					t.Fatal(err)
				}
				if m.UUID != m.Client.UUID {
					t.Fatalf("message UUID %q != client UUID %q", m.UUID, m.Client.UUID)
				}
				return m.Client.UUID
			}

			for i, bound := range []string{testUUIDA, testUUIDB} {
				// a new connection, as dial starts it
				client.Lock()
				client.acked = false
				client.Unlock()

				claim := send()
				if claim != tt.claims[i] {
					t.Errorf("handshake %d claimed %q, want %q", i+1, claim, tt.claims[i])
				}

				ack := claim
				if ack == "" {
					ack = bound
				}
				uuid := ackHandshake(&ron.Client{UUID: ack})

				if got := send(); got != uuid {
					t.Errorf("heartbeat %d after the ack sent %q, want %q", i+1, got, uuid)
				}
			}

			if got := clientUUID(); got != tt.final {
				t.Errorf("client UUID = %q, want %q", got, tt.final)
			}
		})
	}
}

// serveBound acts as the host end of a channel bound to uuid: it answers the
// handshake, sends the UUIDs that the client claimed on claims, and reads
// messages until host closes. Like ron.Server, it refuses another UUID.
func serveBound(host net.Conn, uuid string, claims chan<- [2]string) {
	defer host.Close()

	var magic [3]byte
	if _, err := io.ReadFull(host, magic[:]); err != nil {
		return
	}
	if _, err := io.WriteString(host, "RON"); err != nil {
		return
	}

	enc, dec := gob.NewEncoder(host), gob.NewDecoder(host)

	var m ron.Message
	if err := dec.Decode(&m); err != nil || m.Client == nil {
		return
	}
	claims <- [2]string{m.UUID, m.Client.UUID}

	switch m.Client.UUID {
	case "":
		m.UUID, m.Client.UUID = uuid, uuid
	case uuid:
	default:
		return
	}

	if err := enc.Encode(&m); err != nil {
		return
	}

	for dec.Decode(&m) == nil {
	}
}

// waitBound waits until the client has an acknowledged handshake as want.
func waitBound(t *testing.T, want string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		client.Lock()
		got, acked := client.UUID, client.acked
		client.Unlock()

		if acked && got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("client UUID = %q (acked %v), want %q", got, acked, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestReconnectClaimsNoUUID checks that a client without a claim claims no
// UUID on each connection, and takes the UUID that each connection is bound to.
func TestReconnectClaimsNoUUID(t *testing.T) {
	saveClientFlags(t)
	*f_family, *f_parent, *f_serial, *f_uuid = "unix", "cc", "", ""
	newTestClient("")

	bound := []string{testUUIDA, testUUIDB}
	hosts := make(chan net.Conn, len(bound))
	claims := make(chan [2]string, len(bound))
	stopped := make(chan struct{})

	dialer := netDialer
	calls := 0
	netDialer = func(string, string) (net.Conn, error) {
		if calls == len(bound) {
			// stop the client loop; dial releases the client lock
			close(stopped)
			runtime.Goexit()
		}

		guest, host := net.Pipe()
		go serveBound(host, bound[calls], claims)
		calls++
		hosts <- host

		return guest, nil
	}

	go resetClient()

	for i, want := range bound {
		var host net.Conn
		select {
		case host = <-hosts:
		case <-time.After(10 * time.Second):
			t.Fatalf("connection %d: client did not dial", i+1)
		}

		select {
		case got := <-claims:
			if got != [2]string{} {
				t.Errorf("connection %d: handshake claimed message UUID %q, client UUID %q; want empty", i+1, got[0], got[1])
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("connection %d: no handshake", i+1)
		}

		waitBound(t, want)

		// the connection resets
		host.Close()
	}

	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("client did not reconnect")
	}

	resetClientState()
	netDialer = dialer
}
