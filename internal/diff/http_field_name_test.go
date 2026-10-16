package diff

import (
	"encoding/json"
	"strings"
	"testing"
)

func headerNameSnapshot(t *testing.T, name, value string) []byte {
	t.Helper()
	data, err := json.Marshal(Snapshot{
		Schema: "recondiff.snapshot/v1",
		Assets: []Asset{{
			URL: "https://example.test/login", Status: 200,
			Headers: map[string]string{name: value},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRFC9110FieldNamesAreValidTokens(t *testing.T) {
	scope := []byte(`{"schema":"recondiff.scope/v1","purpose":"authorized synthetic offline test","authorized_origins":["https://example.test"]}`)
	accepted := []string{
		"X-Frame-Options", "x-frame-options", "Custom_Header", "T!#$%&'*+-.^_`|~09", "A", strings.Repeat("A", 128),
	}
	for _, name := range accepted {
		t.Run("valid/"+name, func(t *testing.T) {
			before := headerNameSnapshot(t, name, "DENY")
			after := headerNameSnapshot(t, name, "SAMEORIGIN")
			r, err := Compare(before, after, scope)
			if err != nil {
				t.Fatalf("valid HTTP field name rejected: %v", err)
			}
			if strings.EqualFold(name, "X-Frame-Options") && (r.Summary.Modified != 1 || len(r.Changes) != 1) {
				t.Fatalf("selected valid field must report modification: %#v", r.Summary)
			}
		})
	}
	rejected := []string{
		"", "X-Frame-Options ", " X-Frame-Options", "X Frame Options", "X:Frame", "X/Frame", "X=Frame", "X(Frame)", "X\tFrame", "X\nFrame", "X\x7fFrame", "XéFrame", "X\u200bFrame", strings.Repeat("A", 129),
	}
	for i, name := range rejected {
		_ = i
		t.Run("invalid/"+name, func(t *testing.T) {
			original := headerNameSnapshot(t, name, "DENY")
			valid := headerNameSnapshot(t, "X-Frame-Options", "DENY")
			if _, err := Compare(original, valid, scope); err == nil {
				t.Fatal("malformed before header name silently accepted")
			}
			if _, err := Compare(valid, original, scope); err == nil {
				t.Fatal("malformed after header name silently accepted")
			}
		})
	}
}
