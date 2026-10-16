package diff

import (
	"fmt"
	"strings"
	"testing"
)

// Malformed, untrusted evidence must not contaminate CI diagnostics.
func TestPrivateMalformedValueNeverInDiagnostics(t *testing.T) {
	big := "8" + strings.Repeat("7", 190)
	tests := []struct {
		name, before, scope, secret string
	}{
		{name: "nonstr_header_name", before: `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://fixture.invalid/","status":200,"headers":{"SECRET078-PRIVATE-HEADER":123}}]}`, secret: "SECRET078-PRIVATE-HEADER"},
		{name: "null_header_name", before: `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://fixture.invalid/","status":200,"headers":{"SECRET078-PRIVATE-NULL":null}}]}`, secret: "SECRET078-PRIVATE-NULL"},
		{name: "oversize_numeric_status", before: fmt.Sprintf(`{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://fixture.invalid/","status":%s,"headers":{}}]}`, big), secret: big},
		{name: "oversize_numeric_scope", scope: fmt.Sprintf(`{"schema":"recondiff.scope/v1","purpose":"synthetic","authorized_origins":[%s]}`, big), secret: big},
	}
	validScope := []byte(`{"schema":"recondiff.scope/v1","purpose":"synthetic","authorized_origins":["https://fixture.invalid"]}`)
	validSnapshot := []byte(`{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://fixture.invalid/","status":200,"headers":{}}]}`)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := validSnapshot
			if tt.before != "" {
				before = []byte(tt.before)
			}
			scope := validScope
			if tt.scope != "" {
				scope = []byte(tt.scope)
			}
			_, err := Compare(before, validSnapshot, scope)
			if err == nil {
				t.Fatal("expected invalid evidence rejection")
			}
			if strings.Contains(err.Error(), tt.secret) {
				t.Fatalf("untrusted evidence content leaked to diagnostics: %q", err.Error())
			}
		})
	}
}
