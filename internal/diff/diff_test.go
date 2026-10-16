package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

const scope = `{"schema":"recondiff.scope/v1","purpose":"Synthetic lab only","authorized_origins":["https://example.test","http://[::1]:8080","https://xn--bcher-kva.example"]}`

func snap(assets string) []byte {
	return []byte(`{"schema":"recondiff.snapshot/v1","assets":[` + assets + `]}`)
}
func asset(target string, status int, headers string) string {
	return fmt.Sprintf(`{"url":%q,"status":%d,"headers":{%s}}`, target, status, headers)
}
func compare(t *testing.T, a, b []byte) Result {
	t.Helper()
	r, err := Compare(a, b, []byte(scope))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPositiveStatusAndHeaderDiff(t *testing.T) {
	a := snap(asset("https://example.test/login?password=secret", 200, `"X-Frame-Options":"DENY","Set-Cookie":"PASSWORD=secret"`))
	b := snap(asset("https://example.test/login?token=secret2", 302, `"x-frame-options":"SAMEORIGIN","Set-Cookie":"PASSWORD=other"`))
	r := compare(t, a, b)
	if r.Summary.Modified != 1 || len(r.Changes) != 2 {
		t.Fatalf("unexpected result %+v", r)
	}
	payload, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"password", "secret", "Set-Cookie", "/login", "DENY", "SAMEORIGIN"} {
		if bytes.Contains(bytes.ToLower(payload), bytes.ToLower([]byte(secret))) {
			t.Errorf("sensitive value leaked: %s", secret)
		}
	}
	if r.EvidenceContract != "recondiff.evidence/v1" {
		t.Fatal("evidence contract drift")
	}
}
func TestNoChangeOrderCaseQueryAndIgnoredHeaders(t *testing.T) {
	a := snap(asset("https://EXAMPLE.test:443/path?alpha=A", 200, `"X-Frame-Options":"DENY","Set-Cookie":"A=1"`))
	b := snap(asset("https://example.test/path?alpha=B", 200, `"x-frame-options":"DENY","Set-Cookie":"A=2"`))
	r := compare(t, a, b)
	if len(r.Changes) != 0 {
		t.Fatalf("spurious changes: %+v", r.Changes)
	}
}
func TestAddedAndRemoved(t *testing.T) {
	a := snap(asset("https://example.test/old", 200, ``))
	b := snap(asset("https://example.test/new", 404, ``))
	r := compare(t, a, b)
	if len(r.Changes) != 2 || r.Summary.Added != 1 || r.Summary.Removed != 1 {
		t.Fatalf("unexpected %+v", r)
	}
}
func TestDeterminismAndConcurrency(t *testing.T) {
	a := snap(asset("http://[::1]:8080/", 200, `"Referrer-Policy":"same-origin"`) + "," + asset("https://example.test/", 201, ``))
	b := snap(asset("https://example.test/", 202, ``) + "," + asset("http://[::1]:8080/", 200, `"Referrer-Policy":"strict-origin"`))
	ref, err := Compare(a, b, []byte(scope))
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := JSON(ref)
	var wg sync.WaitGroup
	errors := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := Compare(a, b, []byte(scope))
			if e != nil {
				errors <- e
				return
			}
			got, _ := JSON(r)
			if !bytes.Equal(got, reference) {
				errors <- fmt.Errorf("non-deterministic output")
			}
		}()
	}
	wg.Wait()
	close(errors)
	for e := range errors {
		t.Error(e)
	}
}
func TestScopeEnforcementAndAuthorizationRequirements(t *testing.T) {
	cases := []struct {
		name          string
		before, scope string
	}{
		{"outside scope", string(snap(asset("https://outside.example/", 200, ``))), scope},
		{"missing purpose", string(snap(``)), `{"schema":"recondiff.scope/v1","authorized_origins":["https://example.test"]}`},
		{"empty origins", string(snap(``)), `{"schema":"recondiff.scope/v1","purpose":"lab","authorized_origins":[]}`},
		{"scope includes URL path", string(snap(``)), `{"schema":"recondiff.scope/v1","purpose":"lab","authorized_origins":["https://example.test/foo"]}`},
		{"wrong schema", string(snap(``)), `{"schema":"old","purpose":"lab","authorized_origins":["https://example.test"]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Compare([]byte(c.before), snap(``), []byte(c.scope))
			if err == nil {
				t.Fatal("expected failure")
			}
		})
	}
}
func TestMalformedNegativeBoundary(t *testing.T) {
	bad := []struct {
		name string
		json string
	}{
		{"invalid JSON", `{`},
		{"duplicate top key", `{"schema":"recondiff.snapshot/v1","schema":"recondiff.snapshot/v1","assets":[]}`},
		{"duplicate nested key", `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test","status":200,"status":201,"headers":{}}]}`},
		{"duplicate header", `{"schema":"recondiff.snapshot/v1","assets":[{"url":"https://example.test","status":200,"headers":{"X-Frame-Options":"deny","X-Frame-Options":"allow"}}]}`},
		{"trailing value", `{"schema":"recondiff.snapshot/v1","assets":[]} false`},
		{"unknown field", `{"schema":"recondiff.snapshot/v1","assets":[],"secret_ignored":true}`},
		{"invalid UTF8", string([]byte{0xff})},
		{"bad status", string(snap(asset("https://example.test/", 0, ``)))},
		{"control value", string(snap(asset("https://example.test/", 200, `"Referrer-Policy":"line\nfeed"`)))},
		{"header case duplicates", string(snap(asset("https://example.test/", 200, `"Referrer-Policy":"x","referrer-policy":"y"`)))},
		{"duplicate normalized URLs", string(snap(asset("https://example.test/a?q=1", 200, ``) + "," + asset("https://example.test/a?q=2", 200, ``)))},
		{"userinfo", string(snap(asset("https://alice:secret@example.test/a", 200, ``)))},
		{"unsupported scheme", string(snap(asset("file:///etc/passwd", 200, ``)))},
		{"unicode IDN without punycode", string(snap(asset("https://bücher.example/a", 200, ``)))},
		{"trailing dot", string(snap(asset("https://example.test./a", 200, ``)))},
		{"invalid IPv6 zone", string(snap(asset("http://[fe80::1%25eth0]/", 200, ``)))},
		{"invalid port", string(snap(asset("https://example.test:0/", 200, ``)))},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := Compare([]byte(c.json), snap(``), []byte(scope))
			if err == nil {
				t.Fatalf("invalid input accepted: %s", c.json)
			}
		})
	}
}
func TestLimits(t *testing.T) {
	_, err := ReadBounded(strings.NewReader(strings.Repeat("X", MaxBytes+1)))
	if err == nil {
		t.Fatal("oversize accepted")
	}
	exact, err := ReadBounded(strings.NewReader(strings.Repeat("X", MaxBytes)))
	if err != nil || len(exact) != MaxBytes {
		t.Fatal("exact boundary rejected")
	}
	_, err = ReadBounded(io.LimitReader(&errorReader{}, 1))
	if err == nil {
		t.Fatal("read error suppressed")
	}
	massive := snap(strings.Repeat(asset("https://example.test/a", 200, ``)+",", MaxAssets+1))
	if _, err := Compare(massive, snap(``), []byte(scope)); err == nil {
		t.Fatal("too many assets accepted")
	}
}

type errorReader struct{}

func (*errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestIPv6AndIDNASCIIPunycode(t *testing.T) {
	for _, origin := range []string{"http://[::1]:8080", "https://xn--bcher-kva.example"} {
		a := snap(asset(origin+"/p", 200, ``))
		r := compare(t, a, a)
		if len(r.Changes) != 0 {
			t.Errorf("unexpected changes for %s", origin)
		}
	}
}
func TestHashMatchesExactRawSourcesAndJSON(t *testing.T) {
	a := snap(asset("https://example.test/a", 200, ``))
	b := snap(asset("https://example.test/a", 200, ``))
	r := compare(t, a, b)
	if r.SourceBeforeSHA256 != digest(a) || r.ScopeSHA256 != digest([]byte(scope)) {
		t.Fatal("source digest mismatch")
	}
	wire, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]interface{}
	if err = json.Unmarshal(wire, &v); err != nil {
		t.Fatal(err)
	}
	if v["schema"] != "recondiff.result/v1" {
		t.Fatal("schema drift")
	}
}
