package diff

import "testing"

// RFC 3986 5.2.4 and 6.2.2.3: paths must be compared after removal
// of complete dot segments (including percent-encoded unreserved dots).
func TestRFC3986DotSegmentEquivalence(t *testing.T) {
	cases := []struct {
		name, left, right string
		equal             bool
	}{
		{"parent-segment", "/a/b/../c", "/a/c", true},
		{"current-parent", "/a/x/./../c", "/a/c", true},
		{"encoded-parent", "/a/%2e%2e/c", "/c", true},
		{"mixed-case-encoded", "/a/%2E./c", "/c", true},
		{"dot-at-end", "/a/.", "/a/", true},
		{"parent-at-end", "/a/..", "/", true},
		{"above-root", "/a/../../b", "/b", true},
		{"double-slash-distinct", "/a//c", "/a/c", false},
		{"encoded-slash-distinct", "/a%2Fb/c", "/a/b/c", false},
		{"encoded-percent-no-double-decode", "/a/%252e%252e/c", "/c", false},
		{"dotlike-filename", "/a/.../c", "/a/c", false},
		{"path-case-distinct", "/A/c", "/a/c", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := canonicalURL("https://example.test"+tc.left, false)
			if err != nil {
				t.Fatal(err)
			}
			b, err := canonicalURL("https://example.test"+tc.right, false)
			if err != nil {
				t.Fatal(err)
			}
			if (a == b) != tc.equal {
				t.Fatalf("canonical equivalents = %v, expected %v: %q / %q", a == b, tc.equal, a, b)
			}
		})
	}
}

func TestDotSegmentEquivalentSnapshotNoFalseChanges(t *testing.T) {
	before := snap(asset("https://example.test/a/b/../c", 200, ``))
	after := snap(asset("https://example.test/a/c", 200, ``))
	r := compare(t, before, after)
	if len(r.Changes) != 0 || r.Summary != (Summary{}) {
		t.Fatalf("false changes: %+v", r)
	}
}

func TestDotSegmentDuplicateAssetIsRejected(t *testing.T) {
	before := snap(asset("https://example.test/a/x/../c", 200, ``) + "," + asset("https://example.test/a/c", 200, ``))
	if _, err := Compare(before, snap(``), []byte(scope)); err == nil {
		t.Fatal("dot-segment-equivalent duplicate asset accepted")
	}
}
