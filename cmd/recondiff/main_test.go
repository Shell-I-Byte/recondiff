package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shell-I-Byte/recondiff/internal/diff"
)

func TestCLIRealFilesExitCodesAndPrivateOutput(t *testing.T) {
	dir := t.TempDir()
	before := filepath.Join(dir, "before.json")
	after := filepath.Join(dir, "after.json")
	scope := filepath.Join(dir, "scope.json")
	out := filepath.Join(dir, "report.json")
	entries := []struct{ name, data string }{
		{before, `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/?token=secret","status":200,"headers":{}}]}`},
		{after, `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/?token=secret","status":201,"headers":{}}]}`},
		{scope, `{"schema":"recondiff.scope/v1","purpose":"Lab","authorized_origins":["https://example.test"]}`},
	}
	for _, entry := range entries {
		if err := os.WriteFile(entry.name, []byte(entry.data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	args := []string{"--before", before, "--after", after, "--scope", scope, "--authorized", "--output", out}
	if code := run(args, &stdout, &stderr); code != 2 {
		t.Fatalf("changed exit=%d stderr=%s", code, stderr.String())
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret") {
		t.Fatal("secret echoed in output")
	}
	var report map[string]interface{}
	if err = json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0600 {
		t.Fatalf("unsafe mode %o", stat.Mode().Perm())
	}
	if code := run([]string{"--before", before, "--after", before, "--scope", scope, "--authorized"}, &stdout, &stderr); code != 0 {
		t.Fatalf("unchanged exit=%d stderr=%s", code, stderr.String())
	}
	if code := run([]string{"--before", before, "--after", after, "--scope", scope}, &stdout, &stderr); code != 1 {
		t.Fatal("no authorization accepted")
	}
}
func TestCLIErrorsAndShortWrites(t *testing.T) {
	var out, err bytes.Buffer
	if c := run([]string{"--version"}, &out, &err); c != 0 || !strings.Contains(out.String(), "recondiff "+diff.Version+"\n") {
		t.Fatal("version failed")
	}
	if c := run([]string{"--version"}, &errorWriter{}, &err); c != 1 {
		t.Fatal("version write error ignored")
	}
	if c := run([]string{"--version"}, &shortWriter{}, &err); c != 1 {
		t.Fatal("short version write ignored")
	}
	if e := writeFull(&shortWriter{}, []byte("long report")); e != io.ErrShortWrite {
		t.Fatalf("expected io.ErrShortWrite, got %v", e)
	}
	if c := run([]string{"--garbage"}, &out, &err); c != 1 {
		t.Fatal("invalid flag accepted")
	}
	if e := writeAtomic(filepath.Join(t.TempDir(), "missing", "report.json"), []byte("x")); e == nil {
		t.Fatal("missing output directory accepted")
	}
}

type errorWriter struct{}

func (w *errorWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

type shortWriter struct{}

func (w *shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

// An output destination must never silently destroy one of the evidence inputs.
// This also covers hard links and symlinks pointing to input files.
func TestOutputCannotOverwriteEvidenceInputs(t *testing.T) {
	for _, variant := range []string{"before", "after", "scope", "hardlink", "symlink", "dangling-symlink"} {
		t.Run(variant, func(t *testing.T) {
			dir := t.TempDir()
			before := filepath.Join(dir, "before.json")
			after := filepath.Join(dir, "after.json")
			scope := filepath.Join(dir, "scope.json")
			fixtures := map[string]string{
				before: `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/","status":200,"headers":{}}]}`,
				after:  `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/","status":201,"headers":{}}]}`,
				scope:  `{"schema":"recondiff.scope/v1","purpose":"Local lab","authorized_origins":["https://example.test"]}`,
			}
			for path, fixture := range fixtures {
				if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
					t.Fatal(err)
				}
			}
			dest := map[string]string{"before": before, "after": after, "scope": scope}[variant]
			switch variant {
			case "hardlink":
				dest = filepath.Join(dir, "hardlink.json")
				if err := os.Link(before, dest); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				dest = filepath.Join(dir, "symlink.json")
				if err := os.Symlink(after, dest); err != nil {
					t.Skipf("symlink not supported: %v", err)
				}
			case "dangling-symlink":
				dest = filepath.Join(dir, "dangling.json")
				if err := os.Symlink(filepath.Join(dir, "absent.json"), dest); err != nil {
					t.Skipf("symlink not supported: %v", err)
				}
			}
			var stdout, stderr bytes.Buffer
			exit := run([]string{"--before", before, "--after", after, "--scope", scope, "--authorized", "--output", dest}, &stdout, &stderr)
			if exit != 1 {
				t.Fatalf("unsafe output permitted: exit=%d stderr=%q", exit, stderr.String())
			}
			for path, want := range fixtures {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != want {
					t.Fatalf("modified %s: %v got=%q", path, err, got)
				}
			}
		})
	}
}
