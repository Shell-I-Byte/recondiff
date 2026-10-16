//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicOutputFollowsDirectoryDescriptorNotSymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	escaped := filepath.Join(root, "escaped")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(escaped, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(escaped, link); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(link, "report.json"), []byte("private")); err == nil {
		t.Fatal("accepted symlink output directory")
	}
	if _, err := os.Stat(filepath.Join(escaped, "report.json")); !os.IsNotExist(err) {
		t.Fatalf("wrote outside chosen directory: %v", err)
	}
	if err := writeAtomic(filepath.Join(real, "report.json"), []byte("private")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(real, "report.json"))
	if err != nil || string(data) != "private" {
		t.Fatalf("bad output %q: %v", data, err)
	}
	st, err := os.Stat(filepath.Join(real, "report.json"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("bad permissions %v: %v", st, err)
	}
	if err := writeAtomic(filepath.Join(real, "report.json"), []byte("replaced")); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(real, "report.json"))
	if err != nil || string(data) != "replaced" {
		t.Fatalf("not atomically replaced %q: %v", data, err)
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".recondiff-") {
			t.Fatalf("left temporary file %s", e.Name())
		}
	}
}
