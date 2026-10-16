//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// BUG-RD-086-001: opening an unwritten FIFO must return promptly even if it
// replaces an earlier regular path after a preflight check.
func TestOpenRegularInputNeverBlocksOnFIFO(t *testing.T) {
	if _, err := exec.LookPath("mkfifo"); err != nil {
		t.Skip("mkfifo not available")
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "no-writer.fifo")
	if out, err := exec.Command("mkfifo", fifo).CombinedOutput(); err != nil {
		t.Fatalf("mkfifo: %v %s", err, out)
	}
	for _, path := range []string{fifo, filepath.Join(dir, "fifo-link")} {
		if path != fifo {
			if err := os.Symlink(fifo, path); err != nil {
				t.Skipf("symlinks unsupported: %v", err)
			}
		}
		f, err := openRegularInput(path)
		if f != nil {
			f.Close()
			t.Fatalf("nonregular input opened: %s", path)
		}
		if !errors.Is(err, errInputNotRegular) {
			t.Fatalf("%s: expected regular-file rejection: %v", path, err)
		}
	}
	reg := filepath.Join(dir, "good.json")
	if err := os.WriteFile(reg, []byte(`{"schema":"recondiff.snapshot/v1","assets":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(reg, filepath.Join(dir, "valid-link.json")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	for _, path := range []string{reg, filepath.Join(dir, "valid-link.json")} {
		f, err := openRegularInput(path)
		if err != nil {
			t.Fatalf("valid file %s: %v", path, err)
		}
		f.Close()
	}
	d, err := openRegularInput(dir)
	if d != nil {
		d.Close()
		t.Fatal("directory accepted")
	}
	if !errors.Is(err, errInputNotRegular) {
		t.Fatalf("directory: %v", err)
	}
}
