// Package diff compares two explicitly authorized, offline observations.
// The package performs no DNS queries, requests, scans, or target execution.
package diff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxBytes   = 4 << 20 // Bounded per input, including whitespace.
	MaxAssets  = 10000
	MaxHeaders = 128
	MaxValue   = 2048
	Version    = "0.1.0-rc16"
)

var selectedHeaders = map[string]bool{
	"strict-transport-security": true, "content-security-policy": true,
	"x-frame-options": true, "x-content-type-options": true,
	"referrer-policy": true, "permissions-policy": true,
	"cross-origin-opener-policy": true, "cross-origin-embedder-policy": true,
	"cross-origin-resource-policy": true,
}

type Scope struct {
	Schema            string   `json:"schema"`
	Purpose           string   `json:"purpose"`
	AuthorizedOrigins []string `json:"authorized_origins"`
}
type Snapshot struct {
	Schema string  `json:"schema"`
	Assets []Asset `json:"assets"`
}
type Asset struct {
	URL     string              `json:"url"`
	Status  schemaIntegerStatus `json:"status"`
	Headers map[string]string   `json:"headers"`
}
type Observation struct {
	Origin  string            `json:"origin"`
	ID      string            `json:"asset_id"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"-"` // already SHA-256 digests, never raw values
}
type Change struct {
	AssetID string `json:"asset_id"`
	Origin  string `json:"origin"`
	Kind    string `json:"kind"`
	Field   string `json:"field,omitempty"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}
type Summary struct {
	Added    int `json:"added"`
	Removed  int `json:"removed"`
	Modified int `json:"modified"`
}
type Result struct {
	Schema             string   `json:"schema"`
	EvidenceContract   string   `json:"evidence_contract"`
	SourceBeforeSHA256 string   `json:"source_before_sha256"`
	SourceAfterSHA256  string   `json:"source_after_sha256"`
	ScopeSHA256        string   `json:"scope_sha256"`
	Summary            Summary  `json:"summary"`
	Changes            []Change `json:"changes"`
}

func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

// ReadBounded returns at most MaxBytes input bytes. It refuses exact-overflow
// streams instead of silently truncating JSON and accepts no unlimited reads.
func ReadBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", MaxBytes)
	}
	return b, nil
}

// Reject duplicate object members recursively, including ignored headers.
// Duplicate fields would otherwise silently override prior trusted evidence.
func strictJSON(data []byte, dst interface{}) error {
	if !utf8.Valid(data) {
		return errors.New("JSON must contain valid UTF-8")
	}
	if err := validUTF16JSONEscapes(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := uniqueJSON(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		// Never format an untrusted extra token: a malformed evidence file
		// might contain a credential outside the primary JSON object.
		return errors.New("trailing JSON value or malformed trailing data")
	}
	// encoding/json accepts case-insensitive struct field aliases. A preflight
	// exact-key check is necessary: DisallowUnknownFields alone does not
	// reject {"status":200,"Status":201} as ambiguous evidence.
	if err := exactSchemaKeys(data, dst); err != nil {
		return err
	}
	typed := json.NewDecoder(bytes.NewReader(data))
	typed.DisallowUnknownFields()
	if err := typed.Decode(dst); err != nil {
		// Go encoding/json v1 type errors can embed attacker-supplied numeric
		// values. Never forward those bytes to CI or terminal diagnostics.
		return errors.New("invalid JSON structure or field type")
	}
	if err := typed.Decode(new(interface{})); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

// validUTF16JSONEscapes rejects malformed UTF-16 escape sequences inside JSON
// strings. encoding/json v1 otherwise silently substitutes U+FFFD for isolated
// surrogate escapes, which would misrepresent an immutable evidence value.
// The normal JSON decoder still validates ordinary escapes and JSON syntax.
func validUTF16JSONEscapes(data []byte) error {
	inside := false
	for i := 0; i < len(data); i++ {
		switch {
		case data[i] == '"':
			inside = !inside
		case inside && data[i] == '\\':
			i++
			if i >= len(data) {
				return errors.New("truncated JSON escape")
			}
			if data[i] != 'u' {
				continue
			}
			if i+4 >= len(data) {
				return errors.New("truncated Unicode escape")
			}
			code, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
			if err != nil {
				return errors.New("invalid Unicode escape")
			}
			switch {
			case code >= 0xd800 && code <= 0xdbff:
				if i+10 >= len(data) || data[i+5] != '\\' || data[i+6] != 'u' {
					return errors.New("unpaired high Unicode surrogate")
				}
				low, err := strconv.ParseUint(string(data[i+7:i+11]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return errors.New("invalid low Unicode surrogate")
				}
				i += 10
			case code >= 0xdc00 && code <= 0xdfff:
				return errors.New("unpaired low Unicode surrogate")
			default:
				i += 4
			}
		}
	}
	return nil
}

// exactObject requires the complete, case-sensitive schema key set. It is
// intentionally never used for the dynamic HTTP headers map: header names
// have different protocol normalization rules than JSON schema field names.
func exactObject(raw []byte, required ...string) (map[string]json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return nil, errors.New("expected JSON object")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("invalid JSON object: %w", err)
	}
	allowed := make(map[string]bool, len(required))
	for _, key := range required {
		allowed[key] = true
		if _, exists := obj[key]; !exists {
			return nil, fmt.Errorf("missing required JSON member %q", key)
		}
	}
	for key := range obj {
		if !allowed[key] {
			return nil, errors.New("unexpected/noncanonical JSON member")
		}
	}
	return obj, nil
}

// exactSchemaKeys guards against case-colliding schema aliases, absent
// required arrays, null maps and null arrays (which otherwise decode as nil).
// The canonical field names match the published v1 JSON schemas.
func exactSchemaKeys(data []byte, dst interface{}) error {
	switch dst.(type) {
	case *Scope:
		_, err := exactObject(data, "schema", "purpose", "authorized_origins")
		return err
	case *Snapshot:
		root, err := exactObject(data, "schema", "assets")
		if err != nil {
			return err
		}
		if raw := bytes.TrimSpace(root["assets"]); len(raw) == 0 || raw[0] != '[' {
			return errors.New("snapshot assets must be a JSON array, not missing or null")
		}
		var assets []json.RawMessage
		if err := json.Unmarshal(root["assets"], &assets); err != nil {
			return fmt.Errorf("invalid assets array: %w", err)
		}
		if len(assets) > MaxAssets {
			return errors.New("too many assets")
		}
		for i, raw := range assets {
			asset, err := exactObject(raw, "url", "status", "headers")
			if err != nil {
				return fmt.Errorf("asset %d: %w", i, err)
			}
			if h := bytes.TrimSpace(asset["headers"]); len(h) == 0 || h[0] != '{' {
				return fmt.Errorf("asset %d: headers must be an object, not missing or null", i)
			}
			var headers map[string]json.RawMessage
			if err := json.Unmarshal(asset["headers"], &headers); err != nil {
				return fmt.Errorf("asset %d: invalid header object: %w", i, err)
			}
			for _, raw := range headers {
				if v := bytes.TrimSpace(raw); len(v) == 0 || v[0] != '"' {
					return fmt.Errorf("asset %d: header value must be a JSON string", i)
				}
			}
		}
		return nil
	default:
		return errors.New("unsupported JSON schema destination")
	}
}

func uniqueJSON(dec *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("JSON nesting depth exceeded")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			kTok, err := dec.Token()
			if err != nil {
				return err
			}
			k, ok := kTok.(string)
			if !ok {
				return errors.New("non-string JSON key")
			}
			if _, exists := seen[k]; exists {
				return errors.New("duplicate JSON member")
			}
			seen[k] = struct{}{}
			if len(seen) > MaxAssets*2 {
				return errors.New("too many JSON object members")
			}
			if err := uniqueJSON(dec, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		count := 0
		for dec.More() {
			count++
			if count > MaxAssets+1 {
				return errors.New("JSON array element limit exceeded")
			}
			if err := uniqueJSON(dec, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}

func ParseScope(data []byte) (map[string]bool, error) {
	var s Scope
	if err := strictJSON(data, &s); err != nil {
		return nil, err
	}
	if s.Schema != "recondiff.scope/v1" {
		return nil, errors.New("unsupported scope schema")
	}
	if strings.TrimSpace(s.Purpose) == "" || len(s.Purpose) > 256 || !safeText(s.Purpose) {
		return nil, errors.New("scope purpose required (1-256 printable chars)")
	}
	if len(s.AuthorizedOrigins) == 0 || len(s.AuthorizedOrigins) > 1000 {
		return nil, errors.New("scope must contain 1-1000 origins")
	}
	allowed := make(map[string]bool)
	for _, origin := range s.AuthorizedOrigins {
		canonical, err := canonicalURL(origin, true)
		if err != nil {
			return nil, fmt.Errorf("invalid scope origin: %w", err)
		}
		if allowed[canonical] {
			return nil, errors.New("duplicate authorized origin")
		}
		allowed[canonical] = true
	}
	return allowed, nil
}

// validHTTPFieldName enforces RFC 9110 Section 5.1 field-name = token.
// An apparently security-related name with whitespace or a separator is not
// a valid field and must fail closed, not be silently ignored as unselected.
// ASCII tchar also avoids Unicode case-fold ambiguities in evidence names.
func validHTTPFieldName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func safeText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return false
		}
	}
	return true
}

// canonicalEscapedPath applies only the scheme-independent equivalences of
// RFC 3986 sections 6.2.2.1 and 6.2.2.2. Hex triplets are case-insensitive;
// percent-encodings of unreserved ASCII are interchangeable with literal
// characters. Never decode reserved bytes (especially %2F), percent signs,
// or non-ASCII bytes, and never perform a second decoding pass.
func canonicalEscapedPath(path string) string {
	const upperHex = "0123456789ABCDEF"
	hexValue := func(c byte) byte {
		switch {
		case c >= '0' && c <= '9':
			return c - '0'
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10
		default:
			return c - 'A' + 10
		}
	}
	unreserved := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~'
	}
	var out strings.Builder
	out.Grow(len(path))
	for i := 0; i < len(path); i++ {
		if path[i] != '%' || i+2 >= len(path) {
			out.WriteByte(path[i])
			continue
		}
		// url.URL.EscapedPath returns a valid percent-encoded path, so the
		// two following characters are hexadecimal whenever '%' occurs.
		v := hexValue(path[i+1])<<4 | hexValue(path[i+2])
		if unreserved(v) {
			out.WriteByte(v)
		} else {
			out.WriteByte('%')
			out.WriteByte(upperHex[v>>4])
			out.WriteByte(upperHex[v&15])
		}
		i += 2
	}
	return out.String()
}

// removeDotSegments applies RFC 3986 section 5.2.4 to a percent-normalized,
// still-escaped path. Do this AFTER decoding only unreserved percent escapes,
// since %2E and '.' identify the same segment. RFC processing must retain
// multiple slashes, trailing slashes and encoded reserved bytes (%2F): using
// path.Clean would collapse distinct URI paths.
func removeDotSegments(input string) string {
	output := ""
	removeLast := func() {
		if i := strings.LastIndexByte(output, '/'); i >= 0 {
			output = output[:i]
		} else {
			output = ""
		}
	}
	for input != "" {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = input[2:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"):
			input = input[3:]
			removeLast()
		case input == "/..":
			input = "/"
			removeLast()
		case input == "." || input == "..":
			input = ""
		default:
			// Move the next path segment, including its leading separator,
			// from input to output; preserve adjacent '/' separators.
			offset := 0
			if input[0] == '/' {
				offset = 1
			}
			next := strings.IndexByte(input[offset:], '/')
			if next < 0 {
				output += input
				input = ""
			} else {
				next += offset
				output += input[:next]
				input = input[next:]
			}
		}
	}
	return output
}

// canonicalURL never outputs credentials, query or fragment. The asset ID uses
// the canonical *path*, but the path itself never leaves the input dataset.
// IDNs must be represented in ASCII/Punycode; net/url alone is not an IDNA verifier.
func canonicalURL(input string, originOnly bool) (string, error) {
	if len(input) < 8 || len(input) > 2048 || !safeText(input) {
		return "", errors.New("invalid URL length/control characters")
	}
	u, err := url.Parse(input)
	if err != nil {
		return "", errors.New("failed to parse URL")
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Opaque != "" || u.Host == "" || u.User != nil {
		return "", errors.New("URL requires http(s) authority without credentials")
	}
	if u.RawQuery != "" && originOnly || u.ForceQuery && originOnly || u.Fragment != "" && originOnly || u.Path != "" && originOnly || u.RawPath != "" && originOnly {
		return "", errors.New("scope origin may not include path, query or fragment")
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" || len(hostname) > 253 {
		return "", errors.New("invalid hostname")
	}
	for _, r := range hostname {
		if r > 127 {
			return "", errors.New("international hostnames must use ASCII punycode A-labels")
		}
	}
	if strings.Contains(hostname, "%") {
		return "", errors.New("IPv6 zone identifiers are not allowed")
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		ip, err := netip.ParseAddr(hostname)
		if err != nil || !ip.Is6() {
			return "", errors.New("invalid IPv6 hostname")
		}
		host = "[" + ip.String() + "]"
	} else if ip, err := netip.ParseAddr(hostname); err == nil {
		if !ip.Is4() {
			return "", errors.New("invalid numeric host")
		}
		host = ip.String()
	} else {
		if strings.HasSuffix(hostname, ".") {
			return "", errors.New("trailing-dot host not supported")
		}
		for _, label := range strings.Split(hostname, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errors.New("invalid DNS label")
			}
			for _, r := range label {
				if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
					return "", errors.New("invalid DNS label character")
				}
			}
		}
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid port")
		}
		if !((u.Scheme == "https" && n == 443) || (u.Scheme == "http" && n == 80)) {
			host = net.JoinHostPort(hostname, strconv.Itoa(n))
		}
	}
	origin := u.Scheme + "://" + host
	if originOnly {
		return origin, nil
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if len(path) > 2048 {
		return "", errors.New("URL path too long")
	}
	return origin + removeDotSegments(canonicalEscapedPath(path)), nil
}

func parseSnapshot(raw []byte, allowed map[string]bool) (map[string]Observation, error) {
	var snapshot Snapshot
	if err := strictJSON(raw, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Schema != "recondiff.snapshot/v1" {
		return nil, errors.New("unsupported snapshot schema")
	}
	if len(snapshot.Assets) > MaxAssets {
		return nil, errors.New("too many assets")
	}
	result := make(map[string]Observation, len(snapshot.Assets))
	for i, a := range snapshot.Assets {
		canonical, err := canonicalURL(a.URL, false)
		if err != nil {
			return nil, fmt.Errorf("asset %d: %w", i, err)
		}
		u, _ := url.Parse(canonical)
		origin := u.Scheme + "://" + u.Host
		if !allowed[origin] {
			return nil, fmt.Errorf("asset %d outside authorized origins", i)
		}
		if a.Status < 100 || a.Status > 599 {
			return nil, fmt.Errorf("asset %d invalid status", i)
		}
		if len(a.Headers) > MaxHeaders {
			return nil, fmt.Errorf("asset %d too many headers", i)
		}
		h := make(map[string]string)
		// Sort makes case-insensitive duplicate rejection reproducible.
		keys := make([]string, 0, len(a.Headers))
		for k := range a.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		seen := map[string]bool{}
		for _, k := range keys {
			lower := strings.ToLower(k)
			if !validHTTPFieldName(k) {
				return nil, fmt.Errorf("asset %d invalid header name", i)
			}
			if seen[lower] {
				return nil, fmt.Errorf("asset %d has duplicate case-folded header names", i)
			}
			seen[lower] = true
			v := a.Headers[k]
			if len(v) > MaxValue || !safeText(v) {
				return nil, fmt.Errorf("asset %d invalid header value", i)
			}
			if selectedHeaders[lower] {
				h[lower] = digest([]byte(strings.TrimSpace(v)))
			}
		}
		id := digest([]byte(canonical))
		if _, exists := result[id]; exists {
			return nil, fmt.Errorf("asset %d duplicates normalized URL (queries are ignored)", i)
		}
		result[id] = Observation{Origin: origin, ID: id, Status: int(a.Status), Headers: h}
	}
	return result, nil
}

func status(s int) string { return strconv.Itoa(s) }
func Compare(before, after, scope []byte) (Result, error) {
	allowed, err := ParseScope(scope)
	if err != nil {
		return Result{}, fmt.Errorf("scope: %w", err)
	}
	old, err := parseSnapshot(before, allowed)
	if err != nil {
		return Result{}, fmt.Errorf("before: %w", err)
	}
	now, err := parseSnapshot(after, allowed)
	if err != nil {
		return Result{}, fmt.Errorf("after: %w", err)
	}
	r := Result{Schema: "recondiff.result/v1", EvidenceContract: "recondiff.evidence/v1", SourceBeforeSHA256: digest(before), SourceAfterSHA256: digest(after), ScopeSHA256: digest(scope), Changes: []Change{}}
	all := map[string]bool{}
	for id := range old {
		all[id] = true
	}
	for id := range now {
		all[id] = true
	}
	ids := make([]string, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a, had := old[id]
		b, has := now[id]
		switch {
		case !had:
			r.Summary.Added++
			r.Changes = append(r.Changes, Change{AssetID: id, Origin: b.Origin, Kind: "added"})
		case !has:
			r.Summary.Removed++
			r.Changes = append(r.Changes, Change{AssetID: id, Origin: a.Origin, Kind: "removed"})
		default:
			modified := false
			if a.Status != b.Status {
				modified = true
				r.Changes = append(r.Changes, Change{AssetID: id, Origin: a.Origin, Kind: "changed", Field: "status", Before: status(a.Status), After: status(b.Status)})
			}
			names := map[string]bool{}
			for h := range a.Headers {
				names[h] = true
			}
			for h := range b.Headers {
				names[h] = true
			}
			hs := make([]string, 0, len(names))
			for h := range names {
				hs = append(hs, h)
			}
			sort.Strings(hs)
			for _, h := range hs {
				x, okA := a.Headers[h]
				y, okB := b.Headers[h]
				if okA != okB || x != y {
					modified = true
					kind := "header_changed"
					if !okA {
						kind = "header_added"
					}
					if !okB {
						kind = "header_removed"
					}
					r.Changes = append(r.Changes, Change{AssetID: id, Origin: a.Origin, Kind: kind, Field: h, Before: x, After: y})
				}
			}
			if modified {
				r.Summary.Modified++
			}
		}
	}
	return r, nil
}

// JSON deliberately has no collection timestamp, random IDs, raw paths or raw
// HTTP header values: identical inputs produce byte-identical results.
func JSON(r Result) ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
