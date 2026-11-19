// Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS).
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain
// rights in this software.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBackingName(t *testing.T) {
	cases := []struct {
		image, backing string
		abs            bool
		want           string
	}{
		{"/b/files/saved/a.hdd", "/b/files/x.qcow2", false, "../x.qcow2"},
		{"/b/files/saved/a.hdd", "/b/files/saved/x.qcow2", false, "x.qcow2"},
		{"/b/1/disk-0.qcow2", "/b/files/live/x.qcow2", false, "../files/live/x.qcow2"},
		{"/b/files/saved/a.hdd", "/b/files/x.qcow2", true, "/b/files/x.qcow2"},
	}

	for _, c := range cases {
		got, err := backingName(c.image, c.backing, c.abs)
		if err != nil {
			t.Errorf("backingName(%q, %q, %v): %v", c.image, c.backing, c.abs, err)
			continue
		}
		if got != c.want {
			t.Errorf("backingName(%q, %q, %v) = %q, want %q", c.image, c.backing, c.abs, got, c.want)
		}
	}
}

func TestSavedDiskBacking(t *testing.T) {
	const image = "/b/files/saved/a.hdd"

	cases := []struct {
		name        string
		stored      string
		abs         bool
		wantBacking string
		wantRebase  bool
	}{
		{"no backing file", "", false, "", false},
		{"no backing file, absolute", "", true, "", false},
		{"absolute, clean", "/b/files/x.qcow2", true, "/b/files/x.qcow2", false},
		{"absolute, through instance dir", "/b/13/../files/x.qcow2", true, "/b/files/x.qcow2", true},
		{"absolute, stored relative", "../x.qcow2", true, "/b/files/x.qcow2", true},
		{"relative, through instance dir", "/b/13/../files/x.qcow2", false, "/b/files/x.qcow2", true},
		{"relative, clean", "../x.qcow2", false, "/b/files/x.qcow2", false},
		{"relative, unclean", "../saved/../x.qcow2", false, "/b/files/x.qcow2", true},
		{"relative, stored absolute", "/b/files/x.qcow2", false, "/b/files/x.qcow2", true},
		{"protocol name", "nbd://host/x", false, "", false},
		{"protocol name, absolute", "nbd://host/x", true, "", false},
		{"protocol name, no slashes", "nbd:localhost:10809", false, "", false},
		{"protocol name, socket", "nbd:unix:/b/13/../sock", true, "", false},
		{"relative path with a colon in a directory", "../a:b/x.qcow2", false, "/b/files/a:b/x.qcow2", false},
		{"json name", `json:{"driver":"qcow2","file":{"filename":"/b/13/../files/x.qcow2"}}`, false, "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			backing, rebase, err := savedDiskBacking(image, c.stored, c.abs)
			if err != nil {
				t.Fatal(err)
			}
			if backing != c.wantBacking || rebase != c.wantRebase {
				t.Errorf("savedDiskBacking(%q, %q, %v) = %q, %v, want %q, %v",
					image, c.stored, c.abs, backing, rebase, c.wantBacking, c.wantRebase)
			}
		})
	}
}

// TestFixSavedDiskBacking makes the image chain that "vm save" makes with
// qemu-img, then removes the VM instance directory as "vm flush" does.
func TestFixSavedDiskBacking(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not found")
	}

	for _, abs := range []bool{false, true} {
		name := "relative"
		if abs {
			name = "absolute"
		}

		t.Run(name, func(t *testing.T) {
			setDiskFlags(t, abs)

			base := t.TempDir()
			files := filepath.Join(base, "files")
			*f_iomBase = files
			data := filepath.Join(files, "live", "data.qcow2")
			instance := filepath.Join(base, "13")
			overlay := filepath.Join(instance, "disk-0.qcow2")
			saved := filepath.Join(files, "saved", "c2.hdd")
			for _, d := range []string{filepath.Dir(data), instance, filepath.Dir(saved)} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}

			qemuImg(t, "create", "-f", "qcow2", data, "1M")
			qemuImg(t, "create", "-f", "qcow2", "-b", "../files/live/data.qcow2", "-F", "qcow2", overlay)
			// the backing file name that QEMU writes in the drive-backup target
			unclean := instance + "/../files/live/data.qcow2"
			qemuImg(t, "create", "-f", "qcow2", "-b", unclean, "-F", "qcow2", saved)
			if info, err := diskInfo(saved); err != nil || info.BackingFile != unclean {
				t.Fatalf("before fix: backing file = %q, %v, want %q", info.BackingFile, err, unclean)
			}

			if err := fixSavedDiskBacking(saved); err != nil {
				t.Fatal(err)
			}

			if err := os.RemoveAll(instance); err != nil {
				t.Fatal(err)
			}

			if out, err := exec.Command("qemu-img", "info", "--backing-chain", saved).CombinedOutput(); err != nil {
				t.Fatalf("saved disk is not usable without the instance directory: %v\n%s", err, out)
			}

			want := "../live/data.qcow2"
			if abs {
				want = data
			}
			info, err := diskInfo(saved)
			if err != nil {
				t.Fatal(err)
			}
			if info.BackingFile != want {
				t.Errorf("backing file = %q, want %q", info.BackingFile, want)
			}

			// a second call has nothing to change
			before, err := os.ReadFile(saved)
			if err != nil {
				t.Fatal(err)
			}
			if err := fixSavedDiskBacking(saved); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(saved)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Errorf("second fixSavedDiskBacking changed %v", saved)
			}
		})
	}
}

func setDiskFlags(t *testing.T, abs bool) {
	t.Helper()

	oldAbs, oldBase := *f_absSnapshot, *f_iomBase
	t.Cleanup(func() {
		*f_absSnapshot, *f_iomBase = oldAbs, oldBase
	})

	*f_absSnapshot = abs
}

func qemuImg(t *testing.T, args ...string) {
	t.Helper()

	if out, err := exec.Command("qemu-img", args...).CombinedOutput(); err != nil {
		t.Fatalf("qemu-img %v: %v\n%s", args, err, out)
	}
}
