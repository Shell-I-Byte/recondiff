package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression for privacy and CI log content: invalid evidence must not leak
// raw JSON string tokens or attacker-supplied object member names to stderr.
func TestMalformedJSONDoesNotDisclosePayloadToDiagnostics(t *testing.T) {
	const marker = "RD071-SECRET-FOR-REGRESSION-Z9X8"
	valid := `{"schema":"recondiff.snapshot/v1","assets":[]}`
	scope := `{"schema":"recondiff.scope/v1","purpose":"lab","authorized_origins":["https://example.test"]}`
	for _, tc := range []struct{ name, slot, payload string }{
		{"extra_string_token", "before", valid + ` "` + marker + `"`},
		{"duplicate_member", "before", `{"schema":"recondiff.snapshot/v1","assets":[],"` + marker + `":1,"` + marker + `":2}`},
		{"unknown_member", "before", `{"schema":"recondiff.snapshot/v1","assets":[],"` + marker + `":1}`},
		{"scope_unknown_member", "scope", `{"schema":"recondiff.scope/v1","purpose":"lab","authorized_origins":["https://example.test"],"` + marker + `":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			names := map[string]string{"before": valid, "after": valid, "scope": scope}
			names[tc.slot] = tc.payload
			paths := map[string]string{}
			for slot, data := range names {
				path := filepath.Join(dir, slot+".json")
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				paths[slot] = path
			}
			var stdout, stderr bytes.Buffer
			code := run([]string{"--before", paths["before"], "--after", paths["after"], "--scope", paths["scope"], "--authorized"}, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("expected 1, got %d", code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("invalid evidence produced stdout: %q", stdout.String())
			}
			if strings.Contains(stderr.String(), marker) {
				t.Fatalf("private malformed input leaked to diagnostic: %q", stderr.String())
			}
			if !strings.Contains(stderr.String(), "recondiff:") {
				t.Fatalf("missing error context: %q", stderr.String())
			}
		})
	}
}
