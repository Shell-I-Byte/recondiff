package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// BUG-RD-062-001: a named pipe previously blocked os.Open indefinitely.
// The test invokes the real CLI run function, with a deadline to distinguish
// a prompt rejection from a hang. mkfifo is available on Linux and macOS CI.
func TestCLIRejectsNonregularInputWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not provide POSIX mkfifo")
	}
	mkfifo, err := exec.LookPath("mkfifo")
	if err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	d := t.TempDir()
	files := map[string]string{
		"before": `{"schema":"recondiff.snapshot/v1","assets":[]}`,
		"after":  `{"schema":"recondiff.snapshot/v1","assets":[]}`,
		"scope":  `{"schema":"recondiff.scope/v1","purpose":"local synthetic test","authorized_origins":["https://example.test"]}`,
	}
	args := []string{"--before", filepath.Join(d, "before.json"), "--after", filepath.Join(d, "after.json"), "--scope", filepath.Join(d, "scope.json"), "--authorized"}
	for file, content := range files {
		if err := os.WriteFile(filepath.Join(d, file+".json"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fifo := filepath.Join(d, "never-written.fifo")
	if out, err := exec.Command(mkfifo, fifo).CombinedOutput(); err != nil {
		t.Fatalf("mkfifo: %v %s", err, out)
	}
	link := filepath.Join(d, "linked.fifo")
	if err := os.Symlink(fifo, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, tc := range []struct{ name, flag, path string }{
		{"before FIFO", "--before", fifo}, {"after FIFO", "--after", fifo},
		{"scope FIFO", "--scope", fifo}, {"symlink-to-FIFO", "--before", link},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := append([]string(nil), args...)
			for i := 0; i < len(a)-1; i++ {
				if a[i] == tc.flag {
					a[i+1] = tc.path
					break
				}
			}
			done := make(chan struct{})
			var code int
			var stdout, stderr bytes.Buffer
			go func() { code = run(a, &stdout, &stderr); close(done) }()
			select {
			case <-done:
				if code != 1 || !strings.Contains(stderr.String(), "regular file") || stdout.Len() != 0 {
					t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("CLI blocked on FIFO without a writer")
			}
		})
	}
	// Ordinary symlinks to regular inputs remain supported.
	if err := os.Symlink(filepath.Join(d, "before.json"), filepath.Join(d, "regular-link.json")); err != nil {
		t.Fatal(err)
	}
	args[1] = filepath.Join(d, "regular-link.json")
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("valid symlink rejected: %d %q", code, stderr.String())
	}
}
