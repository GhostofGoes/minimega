// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package meshage

import (
	"encoding/gob"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// pipeLink returns a link on one side of a pipe, and the encoder and decoder
// of the peer on the other side. A goroutine reads the ACKs of the link.
func pipeLink(t *testing.T, timeout time.Duration) (*link, *gob.Encoder, *gob.Decoder, net.Conn) {
	return pipeLinkKeepalive(t, timeout, time.Hour)
}

func pipeLinkKeepalive(t *testing.T, timeout, keepalive time.Duration) (*link, *gob.Encoder, *gob.Decoder, net.Conn) {
	t.Helper()

	a, b := net.Pipe()
	enc := gob.NewEncoder(&deadlineWriter{conn: a, timeout: timeout})
	l := newLink(Control, a, enc, gob.NewDecoder(a), timeout, func() time.Duration { return keepalive })
	t.Cleanup(func() {
		l.close(errLinkClosed)
		b.Close()
	})

	go func() {
		for {
			var m Message
			if err := l.dec.Decode(&m); err != nil {
				l.close(err)
				return
			}
			if m.Command == ACK && m.Seq != 0 {
				l.acked(m.Seq)
			}
		}
	}()

	return l, gob.NewEncoder(b), gob.NewDecoder(b), b
}

// TestLinkWindow sends more than one message before the peer sends an ACK.
// With one message at a time, the peer would never get the second message.
func TestLinkWindow(t *testing.T) {
	const sends = 10

	l, enc, dec, conn := pipeLink(t, 5*time.Second)

	errs := make(chan error, sends)
	for i := 0; i < sends; i++ {
		go func(i int) {
			errs <- l.send(&Message{Command: MESSAGE, Body: strconv.Itoa(i)})
		}(i)
	}

	var seqs []uint64
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for len(seqs) < sends {
		var m Message
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("got %d messages before an ACK, want %d: %v", len(seqs), sends, err)
		}
		seqs = append(seqs, m.Seq)
	}

	for _, seq := range seqs {
		if err := enc.Encode(&Message{Command: ACK, Seq: seq}); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < sends; i++ {
		if err := <-errs; err != nil {
			t.Errorf("send: %v", err)
		}
	}
}

// TestLinkWindowLimit checks that at most WINDOW messages wait for an ACK.
func TestLinkWindowLimit(t *testing.T) {
	l, enc, dec, conn := pipeLink(t, 10*time.Second)

	errs := make(chan error, WINDOW+1)
	for i := 0; i < WINDOW+1; i++ {
		go func() {
			errs <- l.send(&Message{Command: MESSAGE})
		}()
	}

	var first uint64
	for i := 0; i < WINDOW; i++ {
		var m Message
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if i == 0 {
			first = m.Seq
		}
	}

	// The last message must wait for a free place in the window.
	var m Message
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if err := dec.Decode(&m); err == nil {
		t.Fatalf("got message %d with %d messages waiting for an ACK", m.Seq, WINDOW)
	}

	// After a read timeout, net.Pipe can still be read.
	if err := enc.Encode(&Message{Command: ACK, Seq: first}); err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatalf("send: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("no message after an ACK freed a place: %v", err)
	}
}

// TestLinkTimeout checks that a message with no ACK fails with a timeout and
// closes the link.
func TestLinkTimeout(t *testing.T) {
	l, _, dec, _ := pipeLink(t, 200*time.Millisecond)

	go func() {
		for {
			var m Message
			if dec.Decode(&m) != nil {
				return
			}
		}
	}()

	start := time.Now()
	err := l.send(&Message{Command: MESSAGE})
	if !errors.Is(err, errTimeout) {
		t.Fatalf("send = %v, want a timeout", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("timeout after %v, want about 200ms", d)
	}
	if !l.closed() {
		t.Error("link is open after a timeout")
	}
	if err := l.send(&Message{Command: MESSAGE}); err == nil {
		t.Error("send on a closed link succeeded")
	}
}

// TestLinkACKFirst checks that the writer sends a queued ACK before the next
// message.
func TestLinkACKFirst(t *testing.T) {
	l, _, dec, conn := pipeLink(t, 5*time.Second)

	if err := l.ack(7); err != nil {
		t.Fatal(err)
	}
	go l.send(&Message{Command: MESSAGE})

	var m Message
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	if m.Command != ACK || m.Seq != 7 {
		t.Errorf("first message = %v %d, want ACK 7", m.Command, m.Seq)
	}
}

// TestLinkKeepalive checks that an idle link sends a keepalive.
func TestLinkKeepalive(t *testing.T) {
	_, _, dec, conn := pipeLinkKeepalive(t, 5*time.Second, 50*time.Millisecond)

	for i := 0; i < 2; i++ {
		var m Message
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("keepalive %d: %v", i, err)
		}
		if m.Command != ACK || m.Seq != 0 {
			t.Errorf("keepalive %d = %v %d, want ACK 0", i, m.Command, m.Seq)
		}
	}
}

// TestDeadlineWriter writes more than one chunk to a peer that reads slowly.
// Each chunk gets a new deadline, so the write succeeds although it takes
// longer than the timeout.
func TestDeadlineWriter(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	const timeout = 100 * time.Millisecond
	data := make([]byte, 4*writeChunk)

	go func() {
		buf := make([]byte, writeChunk)
		for {
			time.Sleep(timeout / 2)
			if _, err := b.Read(buf); err != nil {
				return
			}
		}
	}()

	w := &deadlineWriter{conn: a, timeout: timeout}
	start := time.Now()
	if n, err := w.Write(data); err != nil || n != len(data) {
		t.Fatalf("Write = %d, %v, want %d, nil", n, err, len(data))
	}
	if d := time.Since(start); d <= timeout {
		t.Errorf("the write took %v; the test needs more than the timeout %v", d, timeout)
	}

	// a peer that stops reading makes the write fail
	b.Close()
	a2, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()

	w = &deadlineWriter{conn: a2, timeout: timeout}
	if _, err := w.Write(data); err == nil {
		t.Error("Write to a peer that does not read succeeded")
	}
}

// TestRegister checks that two nodes that dial each other at the same time
// keep the same control link: the one that the node with the lower name
// dialed.
func TestRegister(t *testing.T) {
	for _, tt := range []struct {
		node, peer string
		oldDialed  bool // this node dialed the existing link
		newDialer  string
		want       bool
	}{
		{"a", "b", true, "b", false},
		{"a", "b", false, "a", true},
		{"b", "a", true, "a", true},
		{"b", "a", false, "b", false},
		{"a", "b", false, "b", true},
		{"a", "b", true, "a", true},
	} {
		n := &Node{name: tt.node, clients: map[string]*client{}}

		old := &client{name: tt.peer, done: make(chan struct{})}
		if tt.oldDialed {
			old.addr = "x"
		}
		n.clients[tt.peer] = old

		c := &client{name: tt.peer, done: make(chan struct{})}
		if got := n.register(c, tt.newDialer); got != tt.want {
			t.Errorf("%+v: register = %v", tt, got)
		}

		want := old
		if tt.want {
			want = c
		}
		if n.clients[tt.peer] != want {
			t.Errorf("%+v: wrong client in the list", tt)
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port
}

// testNodes starts one node for each name. The nodes dial each other on the
// loopback address.
func testNodes(t *testing.T, names ...string) map[string]*Node {
	t.Helper()

	addrs := map[string]string{}
	for _, name := range names {
		addrs[name] = net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))
	}

	var mu sync.Mutex
	nodes := map[string]*Node{}
	for _, name := range names {
		_, port, _ := net.SplitHostPort(addrs[name])
		p, _ := strconv.Atoi(port)

		n := NewNode(name, "test-"+t.Name(), 0, net.IPv4(127, 255, 255, 255), p, "test")
		n.resolve = func(host string) string {
			mu.Lock()
			defer mu.Unlock()

			if addr, ok := addrs[host]; ok {
				return addr
			}
			return host
		}
		nodes[name] = n
	}

	return nodes
}

// waitLinks waits until n has all the links to peer.
func waitLinks(t *testing.T, n *Node, peer string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(n.Links()[peer]) == int(numClasses) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("%v links to %v = %v, want all %d", n.name, peer, n.Links()[peer], numClasses)
}

func dialTest(t *testing.T, a, b *Node) {
	t.Helper()

	var err error
	for i := 0; i < 50; i++ {
		// the listener can start after the node
		if err = a.Dial(b.name); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}

	waitLinks(t, a, b.name)
	waitLinks(t, b, a.name)
}

// classifyPrefix uses the text before ":" in a string body as the class.
func classifyPrefix(body interface{}) Class {
	s, _ := body.(string)
	switch {
	case strings.HasPrefix(s, "bulk:"):
		return Bulk
	case strings.HasPrefix(s, "log:"):
		return Log
	}

	return Control
}

func receive(t *testing.T, n *Node, class Class) *Message {
	t.Helper()

	select {
	case m := <-n.Messages(class):
		return m
	case <-time.After(5 * time.Second):
		t.Fatalf("%v: no %v message", n.name, class)
	}

	return nil
}

func TestNodeLinks(t *testing.T) {
	nodes := testNodes(t, "a", "b")
	a, b := nodes["a"], nodes["b"]
	a.Classify = classifyPrefix

	dialTest(t, a, b)

	for _, body := range []string{"control:1", "bulk:2", "log:3"} {
		class := classifyPrefix(body)

		if _, err := a.Set([]string{"b"}, body); err != nil {
			t.Fatalf("Set %v: %v", body, err)
		}

		m := receive(t, b, class)
		if m.Body != body || m.Class != class {
			t.Errorf("got %v on %v, want %v on %v", m.Body, m.Class, body, class)
		}
	}

	if err := a.Dial("b"); err == nil || !strings.Contains(err.Error(), "already connected") {
		t.Errorf("second dial = %v, want already connected", err)
	}
}

// TestNodeLinkFallback closes the bulk link. Bulk messages then use the
// control link until the node dials the bulk link again.
func TestNodeLinkFallback(t *testing.T) {
	nodes := testNodes(t, "a", "b")
	a, b := nodes["a"], nodes["b"]
	a.Classify = classifyPrefix

	dialTest(t, a, b)

	c, err := a.getClient("b")
	if err != nil {
		t.Fatal(err)
	}
	c.lock.Lock()
	bulk, control := c.links[Bulk], c.links[Control]
	c.lock.Unlock()

	bulk.close(errors.New("test"))
	if l := c.link(Bulk); l != control {
		t.Fatal("bulk message does not use the control link after the bulk link closed")
	}

	if _, err := a.Set([]string{"b"}, "bulk:x"); err != nil {
		t.Fatal(err)
	}
	if m := receive(t, b, Bulk); m.Body != "bulk:x" {
		t.Errorf("got %v, want bulk:x", m.Body)
	}

	waitLinks(t, a, "b")
	waitLinks(t, b, "a")
}

// TestNodeForward sends messages of each class through a node in the middle.
func TestNodeForward(t *testing.T) {
	nodes := testNodes(t, "a", "b", "c")
	a, b, c := nodes["a"], nodes["b"], nodes["c"]
	a.Classify = classifyPrefix

	dialTest(t, a, b)
	dialTest(t, b, c)

	deadline := time.Now().Add(15 * time.Second)
	for {
		a.checkUpdateNetwork()
		a.meshLock.Lock()
		route := a.routes["c"]
		a.meshLock.Unlock()
		if route == "b" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a has no route to c through b: %q", route)
		}
		time.Sleep(50 * time.Millisecond)
	}

	for _, body := range []string{"control:1", "bulk:2", "log:3"} {
		if _, err := a.Set([]string{"c"}, body); err != nil {
			t.Fatalf("Set %v: %v", body, err)
		}
		if m := receive(t, c, classifyPrefix(body)); m.Body != body {
			t.Errorf("got %v, want %v", m.Body, body)
		}
	}
}

// TestNodeHangup checks that all the links close with the control link.
func TestNodeHangup(t *testing.T) {
	nodes := testNodes(t, "a", "b")
	a, b := nodes["a"], nodes["b"]

	dialTest(t, a, b)

	if err := b.Hangup("a"); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for len(a.Links()) > 0 || len(b.Links()) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("links after hangup: a %v, b %v", a.Links(), b.Links())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestDialOldPeer dials a peer that sends the handshake of an older version.
func TestDialOldPeer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		enc := gob.NewEncoder(conn)
		enc.Encode("old")
		enc.Encode(true)
		enc.Encode("old-version")
		time.Sleep(time.Second)
	}()

	nodes := testNodes(t, "a")
	a := nodes["a"]
	a.resolve = func(string) string { return ln.Addr().String() }

	err = a.Dial("old")
	if err == nil || !strings.Contains(err.Error(), "older mesh protocol") {
		t.Fatalf("Dial = %v, want an older mesh protocol error", err)
	}
}
