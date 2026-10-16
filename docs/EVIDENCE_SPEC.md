> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Deterministic evidence — v1

Input: `recondiff.snapshot/v1`, authorization scope `recondiff.scope/v1`.
Output: `recondiff.result/v1` with `evidence_contract: recondiff.evidence/v1`. This is a standalone **observation adapter candidate**, NOT a published ProofGraph Security IR specification.

`source_before_sha256`, `source_after_sha256`, and `scope_sha256` hash the exact original input byte streams (no trimming). `asset_id = lower_hex(SHA256(utf8(canonical_origin + canonical_escaped_path)))`: scheme and host lowercase, default ports dropped, empty path `/`, query and fragment excluded, credentials rejected. Headers are lowercased (case-fold duplicates rejected), allowlisted as defined in `internal/diff/diff.go`, and represented by SHA-256 of the trimmed original value; header names and hash digests are available in result, never raw values. Resource paths are never serialized. Sorting: asset IDs ascending; within modified assets, status then headers ascending; modified asset count increments once regardless of number of per-field changes. Added/removed assets each produce one minimal change entry. No timestamps, random values, remote requests, inferred severity or fabricated evidence.

To replay, retain both unmodified inputs and the scope (with authorized retention controls), rerun the exact binary/source and compare report bytes; input hashes and schema permit tamper detection. Reports have no digital signatures or trusted timestamps. A future ProofGraph importer must treat records as `observed` only and must not promote to `confirmed` without human verification or valid independent corroboration.

### Compatibility

Breaking changes require a new schema/contract version and an explicit migration document. Ignore/acceptance rules are **fail closed** for unknown fields and schemas; version v1 readers must not guess newer semantics.

### Input schema validation tightening (v0.1.0-rc3)
Scope, snapshot, and asset structural JSON members must exactly match the
lowercase member spellings in the published v1 schemas. Case aliases and
Unicode-escaped aliases resolving to noncanonical member spellings are
rejected before `encoding/json` struct decoding. `assets` must be an explicit
array (`[]` is valid); `headers` must be an explicit object (`{}` is valid).
Missing members and JSON `null` are not equivalent to empty collections.
Dynamic HTTP header names are validated separately against RFC 9110 §5.1
ASCII field-name token grammar, including case-folded header-name collision checks.
Malformed names fail closed even if not on the selected security-header allowlist. No evidence-output schema change is involved.

### Input integrity tightening (v0.1.0-rc4)
Reject `null` or other non-string JSON values in the HTTP headers map.
Reject isolated UTF-16 surrogate escapes anywhere in the raw JSON (the Go v1
JSON parser otherwise substitutes U+FFFD). Accept valid high+low surrogate
pairs, and accept literal escaped backslashes. No evidence/output contract
change: the source hashes still describe exact unmodified input bytes.

### Run096 URI-identity correction and migration for pre-v1 candidates

RC10 applies RFC 3986 6.2.2.1–2 normalization **once** to the escaped path:
percent-encoded hex digits become uppercase; any percent-encoded US-ASCII
unreserved character (`A-Z`, `a-z`, `0-9`, `-._~`) is decoded; reserved
characters such as `/`, `?` and `%` are never decoded. No path traversal or
server-specific dot-segment rewrite is performed. The original URL query and
fragment remain excluded. Thus `/a%2fb` equals `/a%2Fb`, and `/%61` equals
`/a`, while `/a%2Fb` differs from `/a/b` and `/%252F` differs from `/%2F`.

**Compatibility warning:** for affected asset paths, this alters SHA-256
`asset_id` values relative to older RC implementations, although the v1 JSON
shape and string labels remain the same. Because `recondiff.evidence/v1` is a
local **pre-release adapter candidate**, not a published frozen contract, no
new shared ProofGraph Security IR is emitted. To migrate archived candidate
evidence: preserve the original unmodified before/after/scope JSON files;
re-run them with the pinned RC10 source/binary; verify source-input hashes;
keep the older RC report as an immutable historical record; do not use
`asset_id` alone to join historical RC evidence across versions. A stable v1
release must freeze/document the canonicalization algorithm and test it.

### RC11 HTTP status numeric semantics

The snapshot schema's `"type":"integer"` follows JSON Schema Draft 2020-12 semantics. An HTTP status of 200, 200.0 or 2e2 denotes the same integer; RC11 accepts each as long as its exact value is in [100,599]. Values with a nonzero fractional part remain invalid. Parsing uses an exact decimal digit algorithm and never float64 rounding. Original source bytes (including lexical representation) still have distinct SHA-256 hashes. No changes to output contract `recondiff.evidence/v1` or asset identity algorithm.

### RC13 URL identity and migration — 2026-10-13

For `asset_id`, compute SHA-256 over the canonical origin plus URL path,
excluding query/fragment and applying (1) RFC 3986 escape-case and unreserved
normalization and then (2) RFC 3986 §5.2.4 removal of complete `.` and `..`
segments. Encoded unreserved dots count as dot segments. Keep repeated `/`
separators and reserved escapes (e.g. `%2F`), and never double-decode.
The old RC12 falsely identified `/a/b/../c` and `/a/c` as different assets.
Existing `asset_id` values for affected RC reports are **not backward
compatible**. Migrate by re-running the original immutable snapshot inputs
with RC13; preserve the original source SHA-256 digests. The v1 result JSON
shape remains unchanged because the stable external contract has not shipped.
Do not silently relabel old reports as RC13-verified.
