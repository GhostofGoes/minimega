// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package iomeshage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// testHasher runs a hasher over a temporary directory with a short hashDelay.
// Files already in the directory are picked up the way startHasher does it.
func testHasher(t *testing.T, base string) (*IOMeshage, *hasher) {
	t.Helper()

	old := hashDelay
	hashDelay = 100 * time.Millisecond
	t.Cleanup(func() { hashDelay = old })

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}

	iom := &IOMeshage{base: base, hash: true, hashes: make(map[string]string)}
	h := newHasher(iom, watcher)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.watch()
	}()

	t.Cleanup(func() {
		watcher.Close()
		<-done
	})

	return iom, h
}

// countHashes wraps the hasher's hash function to count how often it runs.
func countHashes(h *hasher) *atomic.Int64 {
	var n atomic.Int64

	hash := h.hash
	h.hash = func(ctx context.Context, path string) (string, error) {
		n.Add(1)
		return hash(ctx, path)
	}

	return &n
}

func mustHash(t *testing.T, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "want")
	mustWrite(t, path, data)

	hash, err := hashFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}

	return hash
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

// waitHash waits for path to have the wanted hash ("" for none).
func waitHash(t *testing.T, iom *IOMeshage, path, want string) {
	t.Helper()

	var got string

	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if got = iom.getHash(path); got == want {
			return
		}
	}

	t.Fatalf("hash of %v = %q, want %q", path, got, want)
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	mustWrite(t, path, []byte("hello world"))

	hash, err := hashFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 16 {
		t.Errorf("hash = %q, want 16 hex digits", hash)
	}

	// same content, same hash; a symlink is hashed as its target
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if got, err := hashFile(context.Background(), link); err != nil || got != hash {
		t.Errorf("hash via symlink = %q, %v, want %q", got, err, hash)
	}

	mustWrite(t, path, []byte("hello world!"))
	if got, err := hashFile(context.Background(), path); err != nil || got == hash {
		t.Errorf("hash of different content = %q, %v, want it to differ from %q", got, err, hash)
	}

	if _, err := hashFile(context.Background(), filepath.Join(dir, "missing")); err == nil {
		t.Error("hashing a missing file did not fail")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hashFile(ctx, path); !errors.Is(err, context.Canceled) {
		t.Errorf("hashing with a cancelled context: %v, want context.Canceled", err)
	}
}

func TestIgnoreDirectory(t *testing.T) {
	tests := map[string]bool{
		"/files/transfer_123":          true,
		"/files/transfer_123/foo.part": true,
		"/files/foo.qc2":               false,
		"/files/my_transfer_notes.txt": false,
		"/files/images/file_transfer_": false,
	}

	for path, want := range tests {
		if got := ignoreDirectory(path); got != want {
			t.Errorf("ignoreDirectory(%q) = %v, want %v", path, got, want)
		}
	}
}

// Files that exist when the hasher starts are hashed, except the ones that
// never were: empty files, symlinks and in-flight transfers.
func TestHasherExistingFiles(t *testing.T) {
	base := t.TempDir()

	mustWrite(t, filepath.Join(base, "top"), []byte("top"))
	mustWrite(t, filepath.Join(base, "a", "b", "nested"), []byte("nested"))
	mustWrite(t, filepath.Join(base, "empty"), nil)
	mustWrite(t, filepath.Join(base, "transfer_1", "part"), []byte("part"))
	if err := os.Symlink(filepath.Join(base, "top"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}

	iom, h := testHasher(t, base)
	h.addDir(base)

	waitHash(t, iom, filepath.Join(base, "top"), mustHash(t, []byte("top")))
	waitHash(t, iom, filepath.Join(base, "a", "b", "nested"), mustHash(t, []byte("nested")))

	// relative paths are looked up below the base directory
	if got := iom.getHash("a/b/nested"); got != mustHash(t, []byte("nested")) {
		t.Errorf("hash by relative path = %q", got)
	}

	for _, f := range []string{"empty", "link", "transfer_1/part"} {
		if got := iom.getHash(f); got != "" {
			t.Errorf("%v was hashed: %q", f, got)
		}
	}
}

// A file written in many small chunks is hashed once, after the last write,
// not once per write (sandia-minimega/minimega#1677).
func TestHasherHashesOnceAfterWrites(t *testing.T) {
	base := t.TempDir()
	iom, h := testHasher(t, base)
	runs := countHashes(h)
	h.addDir(base)

	path := filepath.Join(base, "big.img")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	chunk := bytes.Repeat([]byte("x"), 4096)

	var data []byte

	// writes are closer together than hashDelay, like a copy in progress
	for i := 0; i < 50; i++ {
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}

		data = append(data, chunk...)
		time.Sleep(hashDelay / 10)

		if got := iom.getHash(path); got != "" {
			t.Fatalf("file has hash %q while it is still being written", got)
		}
	}

	waitHash(t, iom, path, mustHash(t, data))

	// give any extra hashes a chance to show up
	time.Sleep(3 * hashDelay)

	if n := runs.Load(); n != 1 {
		t.Errorf("file was hashed %d times, want 1", n)
	}
}

// A hash in progress is abandoned when the file changes underneath it, and
// its result never replaces the hash of the newer content.
func TestHasherChangeWhileHashing(t *testing.T) {
	base := t.TempDir()
	iom, h := testHasher(t, base)

	started := make(chan struct{}, 16)
	cancelled := make(chan struct{}, 16)

	var block atomic.Bool
	block.Store(true)

	hash := h.hash
	h.hash = func(ctx context.Context, path string) (string, error) {
		if block.Load() {
			started <- struct{}{}
			<-ctx.Done()
			cancelled <- struct{}{}

			// a slow hash of the old content finishing late
			return "stale", nil
		}

		return hash(ctx, path)
	}

	h.addDir(base)

	path := filepath.Join(base, "file")
	mustWrite(t, path, []byte("old"))

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("file was never hashed")
	}

	block.Store(false)
	mustWrite(t, path, []byte("new content"))

	select {
	case <-cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("hash in progress was not cancelled when the file changed")
	}

	waitHash(t, iom, path, mustHash(t, []byte("new content")))
}

func TestHasherRemoveAndRename(t *testing.T) {
	base := t.TempDir()
	iom, h := testHasher(t, base)
	h.addDir(base)

	want := mustHash(t, []byte("data"))

	file := filepath.Join(base, "file")
	mustWrite(t, file, []byte("data"))
	waitHash(t, iom, file, want)

	// renaming a file moves its hash
	moved := filepath.Join(base, "moved")
	if err := os.Rename(file, moved); err != nil {
		t.Fatal(err)
	}
	waitHash(t, iom, moved, want)
	waitHash(t, iom, file, "")

	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
	waitHash(t, iom, moved, "")

	// renaming a directory moves the hashes of the files in it
	inDir := filepath.Join(base, "dir", "sub", "file")
	mustWrite(t, inDir, []byte("data"))
	waitHash(t, iom, inDir, want)

	if err := os.Rename(filepath.Join(base, "dir"), filepath.Join(base, "dir2")); err != nil {
		t.Fatal(err)
	}
	waitHash(t, iom, filepath.Join(base, "dir2", "sub", "file"), want)
	waitHash(t, iom, inDir, "")

	// and files added to the renamed directory are hashed under its new name
	added := filepath.Join(base, "dir2", "sub", "added")
	mustWrite(t, added, []byte("data"))
	waitHash(t, iom, added, want)
	if got := iom.getHash(filepath.Join(base, "dir", "sub", "added")); got != "" {
		t.Errorf("file added after the rename has a hash under the old directory name: %q", got)
	}

	// a file removed before it was hashed gets no hash
	gone := filepath.Join(base, "gone")
	mustWrite(t, gone, []byte("data"))
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * hashDelay)
	if got := iom.getHash(gone); got != "" {
		t.Errorf("removed file has hash %q", got)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.jobs) != 0 {
		t.Errorf("%d hash jobs left behind", len(h.jobs))
	}
}

// A timer that fired for a job that has since been replaced must not hash on
// behalf of the new job, whose quiet period has not passed yet.
func TestHasherStaleTimer(t *testing.T) {
	base := t.TempDir()
	_, h := testHasher(t, base)
	runs := countHashes(h)

	path := filepath.Join(base, "file")
	mustWrite(t, path, []byte("data"))

	stale := &hashJob{gen: 1}
	h.jobs[path] = &hashJob{gen: 1}

	h.run(path, stale, 1)

	if n := runs.Load(); n != 0 {
		t.Errorf("stale timer hashed the file %d times", n)
	}
	if h.jobs[path] == nil {
		t.Error("stale timer removed the current job")
	}
}

// Files that land in a directory right after it is created are hashed even
// though the directory is not being watched yet.
func TestHasherNewDirectoryWithContent(t *testing.T) {
	base := t.TempDir()
	iom, h := testHasher(t, base)
	h.addDir(base)

	want := mustHash(t, []byte("data"))

	for i := 0; i < 20; i++ {
		path := filepath.Join(base, "new", string(rune('a'+i)), "deep", "file")
		mustWrite(t, path, []byte("data"))
	}

	for i := 0; i < 20; i++ {
		waitHash(t, iom, filepath.Join(base, "new", string(rune('a'+i)), "deep", "file"), want)
	}
}

// No more than hashWorkers files are hashed at the same time.
func TestHasherWorkerLimit(t *testing.T) {
	base := t.TempDir()

	const files = 32

	for i := 0; i < files; i++ {
		mustWrite(t, filepath.Join(base, string(rune('a'+i))), []byte("data"))
	}

	iom, h := testHasher(t, base)

	var (
		mu           sync.Mutex
		running, max int
	)

	hash := h.hash
	h.hash = func(ctx context.Context, path string) (string, error) {
		mu.Lock()
		running++
		if running > max {
			max = running
		}
		mu.Unlock()

		time.Sleep(20 * time.Millisecond)

		mu.Lock()
		running--
		mu.Unlock()

		return hash(ctx, path)
	}

	h.addDir(base)

	want := mustHash(t, []byte("data"))
	for i := 0; i < files; i++ {
		waitHash(t, iom, filepath.Join(base, string(rune('a'+i))), want)
	}

	mu.Lock()
	defer mu.Unlock()

	if max > hashWorkers {
		t.Errorf("%d files hashed at once, limit is %d", max, hashWorkers)
	}
}

// A relative base directory must not change which hash a file name maps to.
func TestNewRelativeBase(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	iom, err := New("files", nil, "", false)
	if err != nil {
		t.Fatal(err)
	}

	if want := filepath.Join(dir, "files"); iom.base != want {
		// TempDir may itself be reached through a symlink
		if real, _ := filepath.EvalSymlinks(want); iom.base != real {
			t.Fatalf("base = %q, want %q", iom.base, want)
		}
	}

	// the hasher stores hashes by the path it watches, Get looks them up by name
	iom.updateHash(filepath.Join(iom.base, "foo.qc2"), "abc")
	if got := iom.getHash("foo.qc2"); got != "abc" {
		t.Errorf("hash by name = %q, want abc", got)
	}

	iom.updateHash(filepath.Join(iom.base, "dir", "bar"), "def")
	iom.deleteHashes("dir")
	if got := iom.getHash("dir/bar"); got != "" {
		t.Errorf("hash survived deleting its directory: %q", got)
	}
	if got := iom.getHash("foo.qc2"); got != "abc" {
		t.Errorf("deleting a directory dropped an unrelated hash")
	}
}
