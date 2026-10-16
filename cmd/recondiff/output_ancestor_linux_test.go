//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression for intermediary directory symlinks: O_NOFOLLOW on the final
// directory alone is not sufficient to prevent reports leaving their parent.
func TestAtomicOutputRejectsAncestorSymlink(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "good")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(good, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(good, "alias")
	if err := os.Symlink(outside, alias); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(alias, "nested", "report.json")
	if err := writeAtomic(target, []byte("SYNTHETIC-OUTSIDE-SENTINEL")); err == nil {
		t.Fatal("accepted ancestor symlink; output escaped intended directory")
	}
	if _, err := os.Lstat(filepath.Join(outside, "nested", "report.json")); !os.IsNotExist(err) {
		t.Fatalf("escaped file was created: %v", err)
	}
}

func TestAtomicOutputRejectsLexicalParentTraversal(t *testing.T) {
	root := t.TempDir()
	permitted := filepath.Join(root, "permitted")
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(permitted, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	// Do not filepath.Clean: retaining the literal parent token is the test.
	target := permitted + "/../outside/report.json"
	if !strings.Contains(target, "/../") {
		t.Fatal("test setup lost parent token")
	}
	if err := writeAtomic(target, []byte("SYNTHETIC-TRAVERSAL-SENTINEL")); err == nil {
		t.Fatal("accepted lexical .. component in output pathname")
	}
	if _, err := os.Lstat(filepath.Join(outside, "report.json")); !os.IsNotExist(err) {
		t.Fatalf("file created after traversal: %v", err)
	}
}

func TestAtomicOutputRegularNestedDirectoryStillWorks(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "p", "q", "r")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(nested, "report.json")
	if err := writeAtomic(target, []byte("synthetic report")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "synthetic report" {
		t.Fatalf("unexpected output: %q %v", b, err)
	}
}
