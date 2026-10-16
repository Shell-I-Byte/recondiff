package diff

import (
	"strings"
	"testing"
)

func TestJSONSchemaHTTPStatusIntegerRepresentation(t *testing.T) {
	scope := []byte(`{"schema":"recondiff.scope/v1","purpose":"synthetic","authorized_origins":["https://example.test"]}`)
	cases := []struct {
		literal string
		ok      bool
	}{
		{"200", true}, {"200.0", true}, {"2e2", true},
		{"2E+2", true}, {"5.99e2", true}, {"200.0000000000000000000000000", true},
		{"0.002e5", true}, {"1.00e2", true}, {"599.0000000", true},
		{"200.00000000000000000000001", false},
		{"199.999999999999999999999999", false},
		{"599.00000000000000000000001", false},
		{"99.0", false}, {"600.0", false}, {"2e999999", false},
		{"2e-999999", false}, {"1.999e2", false},
		{"null", false}, {`"200"`, false}, {"true", false}, {"-0.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.literal, func(t *testing.T) {
			snap := `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/a","status":` + tc.literal + `,"headers":{}}]}`
			_, err := Compare([]byte(snap), []byte(snap), scope)
			if (err == nil) != tc.ok {
				t.Fatalf("status %s: want accepted=%t, got error %v", tc.literal, tc.ok, err)
			}
			if err != nil && strings.Contains(err.Error(), tc.literal) && tc.literal != "null" {
				t.Fatalf("status leaked raw numeric text: %v", err)
			}
		})
	}
}

func TestJSONSchemaStatusEquivalentRepresentationsNoFalseDiff(t *testing.T) {
	scope := []byte(`{"schema":"recondiff.scope/v1","purpose":"synthetic","authorized_origins":["https://example.test"]}`)
	base := `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/a","status":200,"headers":{}}]}`
	altered := strings.Replace(base, `"status":200`, `"status":2e2`, 1)
	r, err := Compare([]byte(base), []byte(altered), scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Changes) != 0 || r.Summary.Modified != 0 {
		t.Fatalf("equivalent integer representation produced differences: %+v", r)
	}
	if r.SourceBeforeSHA256 == r.SourceAfterSHA256 {
		t.Fatal("exact original input hashes unexpectedly equal")
	}
}
