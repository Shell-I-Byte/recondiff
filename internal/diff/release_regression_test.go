package diff

import (
	"bytes"
	"fmt"
	"testing"
)

// BUG-RD-FOCUS-001: structural schema keys are case-sensitive and unique.
// A map of HTTP header names is different: its keys are dynamic, not schema fields.
func TestReleaseStructuralJSONKeysExact(t *testing.T) {
	checks := []struct {
		name   string
		scope  string
		before string
	}{
		{"scope conflicting purpose aliases", `{"schema":"recondiff.scope/v1","purpose":"Synthetic lab","Purpose":"alternate","authorized_origins":["https://example.test"]}`, string(snap(``))},
		{"scope equal purpose aliases", `{"schema":"recondiff.scope/v1","purpose":"Synthetic lab","Purpose":"Synthetic lab","authorized_origins":["https://example.test"]}`, string(snap(``))},
		{"scope wrong-case-only origins", `{"schema":"recondiff.scope/v1","purpose":"Synthetic lab","Authorized_Origins":["https://example.test"]}`, string(snap(``))},
		{"snapshot conflicting schema aliases", scope, `{"schema":"old","Schema":"recondiff.snapshot/v1","assets":[]}`},
		{"snapshot equal schema aliases", scope, `{"schema":"recondiff.snapshot/v1","Schema":"recondiff.snapshot/v1","assets":[]}`},
		{"snapshot wrong-case assets", scope, `{"schema":"recondiff.snapshot/v1","Assets":[]}`},
		{"asset status aliases", scope, `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/","status":200,"Status":201,"headers":{}}]}`},
		{"asset URL wrong-case", scope, `{"schema":"recondiff.snapshot/v1","assets":[{"URL":"https://example.test/","status":200,"headers":{}}]}`},
		{"asset escaped alias", scope, `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/","status":200,"St\u0061tus":201,"headers":{}}]}`},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			_, err := Compare([]byte(c.before), snap(``), []byte(c.scope))
			if err == nil {
				t.Fatalf("ambiguous/noncanonical JSON accepted: %s", c.before)
			}
		})
	}
	t.Run("valid distinct header keys", func(t *testing.T) {
		before := snap(asset("https://example.test/", 200, `"X-Frame-Options":"DENY","Referrer-Policy":"no-referrer"`))
		if _, err := Compare(before, before, []byte(scope)); err != nil {
			t.Fatalf("valid JSON header map rejected: %v", err)
		}
	})
}

// BUG-RD-FOCUS-002: absent/null arrays cannot mean a valid empty inventory.
func TestReleaseRequiredSnapshotArray(t *testing.T) {
	bad := []struct{ name, raw string }{
		{"missing", `{"schema":"recondiff.snapshot/v1"}`},
		{"null", `{"schema":"recondiff.snapshot/v1","assets":null}`},
		{"wrong type", `{"schema":"recondiff.snapshot/v1","assets":{}}`},
		{"asset missing headers", `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/","status":200}]}`},
		{"asset null headers", `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/","status":200,"headers":null}]}`},
	}
	nonempty := snap(asset("https://example.test/", 200, ``))
	for _, c := range bad {
		for _, order := range []string{"before", "after"} {
			t.Run(c.name+"/"+order, func(t *testing.T) {
				old, now := nonempty, []byte(c.raw)
				if order == "before" {
					old, now = []byte(c.raw), nonempty
				}
				if r, e := Compare(old, now, []byte(scope)); e == nil {
					t.Fatalf("bad %s accepted, report=%+v", order, r.Summary)
				}
			})
		}
	}
	t.Run("explicit empty is a valid removal", func(t *testing.T) {
		r, e := Compare(nonempty, snap(``), []byte(scope))
		if e != nil || r.Summary.Removed != 1 {
			t.Fatalf("valid empty list rejected: %v %+v", e, r.Summary)
		}
	})
	t.Run("canonical JSON output stays deterministic", func(t *testing.T) {
		a := snap(asset("https://example.test/", 200, `"Referrer-Policy":"no-referrer"`))
		r, e := Compare(a, a, []byte(scope))
		if e != nil {
			t.Fatal(e)
		}
		b, e := JSON(r)
		if e != nil {
			t.Fatal(e)
		}
		r2, e := Compare(a, a, []byte(scope))
		if e != nil {
			t.Fatal(e)
		}
		b2, e := JSON(r2)
		if e != nil || !bytes.Equal(b, b2) {
			t.Fatal(fmt.Sprint("unstable output", e))
		}
	})
}

// A JSON null is not an empty HTTP header value. Silently interpreting it as
// an empty string creates a false observation and misleading evidence hash.
func TestReleaseRejectNullHeaderValues(t *testing.T) {
	scope := []byte(`{"schema":"recondiff.scope/v1","purpose":"synthetic test","authorized_origins":["https://example.test"]}`)
	ok := []byte(`{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/","status":200,"headers":{"x-frame-options":"DENY"}}]}`)
	malformed := []byte(`{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/","status":200,"headers":{"x-frame-options":null}}]}`)
	if _, err := Compare(ok, malformed, scope); err == nil {
		t.Fatal("null header value was silently accepted as an empty observation")
	}
	if _, err := Compare(malformed, ok, scope); err == nil {
		t.Fatal("null header value was silently accepted in before snapshot")
	}
	if _, err := Compare(ok, ok, scope); err != nil {
		t.Fatalf("canonical header-string control rejected: %v", err)
	}
}

// A lone surrogate is not a Unicode scalar value. encoding/json v1 replaces
// it with U+FFFD, which can make malformed evidence look like a valid header.
func TestReleaseRejectUnpairedJSONSurrogates(t *testing.T) {
	scope := []byte(`{"schema":"recondiff.scope/v1","purpose":"synthetic test","authorized_origins":["https://example.test"]}`)
	original := []byte(`{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/","status":200,"headers":{"x-frame-options":"ok"}}]}`)
	for _, tc := range []struct{ name, encoded string }{
		{"lone high", `\uD800`},
		{"lone low", `\uDC00`},
		{"high followed by ordinary char", `\uD800x`},
		{"two highs", `\uD800\uD801`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			malformed := []byte(`{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/","status":200,"headers":{"x-frame-options":"` + tc.encoded + `"}}]}`)
			if _, err := Compare(original, malformed, scope); err == nil {
				t.Fatalf("accepted ill-formed surrogate escape %s", tc.encoded)
			}
		})
	}
	properPair := []byte(`{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test/","status":200,"headers":{"x-frame-options":"\uD83D\uDE00"}}]}`)
	if _, err := Compare(original, properPair, scope); err != nil {
		t.Fatalf("valid supplementary surrogate pair rejected: %v", err)
	}
}
