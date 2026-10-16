package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CLI diagnostics are untrusted-input surfaces. They must not allow malformed
// flags, filesystem names or decoded JSON strings to forge CI/terminal lines.
func TestUntrustedDiagnosticsCannotForgeTerminalOutput(t *testing.T) {
	dir := t.TempDir()
	before := filepath.Join(dir, "before.json")
	after := filepath.Join(dir, "after.json")
	scope := filepath.Join(dir, "scope.json")
	for name, value := range map[string]string{
		before: `{"schema":"recondiff.snapshot/v1","assets":[]} "INJECT\nCI-GREEN-FAKE"`,
		after:  `{"schema":"recondiff.snapshot/v1","assets":[]}`,
		scope:  `{"schema":"recondiff.scope/v1","purpose":"Lab","authorized_origins":["https://example.test"]}`,
	} {
		if err := os.WriteFile(name, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		args []string
	}{
		{"flag_newline", []string{"--BAD\nCI-PASS-FAKE"}},
		{"flag_ansi", []string{"--BAD\x1b[31mRED"}},
		{"flag_bidi", []string{"--BAD\u202eVISUAL"}},
		{"input_filename", []string{"--before", filepath.Join(dir, "missing\nGATE-PASS-FAKE"), "--after", after, "--scope", scope, "--authorized"}},
		{"decoded_JSON", []string{"--before", before, "--after", after, "--scope", scope, "--authorized"}},
		{"output_filename", []string{"--before", after, "--after", after, "--scope", scope, "--authorized", "--output", filepath.Join(dir, "missing\nOUTPUT-PASS-FAKE", "report.json")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != 1 {
				t.Fatalf("exit=%d stderr=%q", got, stderr.String())
			}
			message := stderr.String()
			if got := strings.Count(message, "\n"); got != 1 {
				t.Errorf("expected one diagnostic line, got %d: %q", got, message)
			}
			if strings.ContainsRune(message, '\x1b') || strings.ContainsRune(message, '\u202e') || strings.ContainsRune(message, '\r') {
				t.Errorf("terminal controls leaked: %q", message)
			}
			if stdout.Len() != 0 {
				t.Errorf("unexpected stdout: %q", stdout.String())
			}
		})
	}
}

func TestHelpIsTrustedAndFunctional(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--help"}, &stdout, &stderr); got != 0 {
		t.Fatalf("--help exit=%d stderr=%q", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--authorized") && !strings.Contains(stderr.String(), "-authorized") {
		t.Fatalf("trusted help missing authorization option: %q", stderr.String())
	}
}
