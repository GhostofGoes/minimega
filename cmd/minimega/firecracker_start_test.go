// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestFCInstanceStartLimit starts more VMs than the limit. The starts take
// longer in total than the API timeout, but each request is shorter, so all
// of them must succeed.
func TestFCInstanceStartLimit(t *testing.T) {
	oldParallel := *f_firecrackerLaunchParallel
	t.Cleanup(func() {
		*f_firecrackerLaunchParallel = oldParallel
		fcStartSem = fcSemaphore{}
	})
	*f_firecrackerLaunchParallel = 2
	fcStartSem = fcSemaphore{}

	const (
		starts  = 10
		work    = 150 * time.Millisecond
		timeout = 500 * time.Millisecond
	)

	var mu sync.Mutex
	running, most := 0, 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/actions" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mu.Lock()
		running++
		most = max(most, running)
		mu.Unlock()

		time.Sleep(work)

		mu.Lock()
		running--
		mu.Unlock()

		w.WriteHeader(http.StatusNoContent)
	})

	// A short directory keeps the socket path under the size limit.
	dir, err := os.MkdirTemp("", "fcs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	sock := filepath.Join(dir, "api.sock")
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = fcListen(t, sock)
	srv.Start()
	t.Cleanup(srv.Close)

	errs := make(chan error, starts)
	begin := time.Now()
	for range starts {
		go func() {
			c := newFCClient(sock)
			c.timeout = timeout
			errs <- fcInstanceStart(c)
		}()
	}
	for range starts {
		if err := <-errs; err != nil {
			t.Errorf("fcInstanceStart() = %v", err)
		}
	}

	if most != 2 {
		t.Errorf("at most %d InstanceStart requests ran at the same time, want 2", most)
	}
	if d := time.Since(begin); d <= timeout {
		t.Errorf("the starts took %v; the test needs more than the timeout %v", d, timeout)
	}
}
