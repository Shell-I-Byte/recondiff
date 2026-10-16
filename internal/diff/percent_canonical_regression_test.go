package diff

import "testing"

// RFC 3986 §§ 2.3, 6.2.2.1–2: escape hex case is irrelevant and escaped
// unreserved ASCII identifies the same URI. Reserved escapes stay distinct.
func TestURIPercentEncodingEquivalence(t *testing.T) {
	cases := []struct {
		name, left, right string
		equal             bool
	}{
		{"percent-case-reserved", "https://example.test/a%2fb", "https://example.test/a%2Fb", true},
		{"escaped-unreserved-letter", "https://example.test/%61", "https://example.test/a", true},
		{"escaped-unreserved-tilde", "https://example.test/%7e", "https://example.test/~", true},
		{"escaped-unreserved-dot", "https://example.test/%2e", "https://example.test/.", true},
		{"reserved-slash-remains-encoded", "https://example.test/a%2Fb", "https://example.test/a/b", false},
		{"do-not-double-decode", "https://example.test/%252F", "https://example.test/%2F", false},
		{"escaped-percent-case", "https://example.test/%25a", "https://example.test/%25A", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			left, err := canonicalURL(tc.left, false)
			if err != nil {
				t.Fatal(err)
			}
			right, err := canonicalURL(tc.right, false)
			if err != nil {
				t.Fatal(err)
			}
			if (left == right) != tc.equal {
				t.Errorf("URI equivalence mismatch: %q == %q: %v, want %v", left, right, left == right, tc.equal)
			}
		})
	}
}

func TestURIPercentEquivalentSnapshotNoFalseChanges(t *testing.T) {
	a := snap(asset("https://example.test/a%2fb", 200, ``))
	b := snap(asset("https://example.test/a%2Fb", 200, ``))
	result := compare(t, a, b)
	if len(result.Changes) != 0 {
		t.Fatalf("equivalent URIs produced false add/remove: %+v", result.Summary)
	}
	a = snap(asset("https://example.test/%61", 200, ``))
	b = snap(asset("https://example.test/a", 200, ``))
	result = compare(t, a, b)
	if len(result.Changes) != 0 {
		t.Fatalf("unreserved escape produced false add/remove: %+v", result.Summary)
	}
}

func TestURIPercentEquivalentAssetsCannotDuplicateSnapshot(t *testing.T) {
	a := snap(asset("https://example.test/%61", 200, ``) + "," + asset("https://example.test/a", 200, ``))
	if _, err := Compare(a, snap(``), []byte(scope)); err == nil {
		t.Fatal("percent-equivalent duplicate asset accepted")
	}
}
