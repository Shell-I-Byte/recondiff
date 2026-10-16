> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc10 — unreleased release candidate (2026-10-11)

Fixes BUG-RD-096-001, a **confirmed evidence-accuracy defect**. Compiled RC9
reported false resource added/removed pairs for RFC 3986-equivalent paths
`/a%2fb` vs `/a%2Fb` and `/%61` vs `/a`. The dedicated Go regression was
RED against RC9; RC10 changes `canonicalEscapedPath` to uppercase hex triplets
and decode only unreserved ASCII, then passes targeted and independent CLI
positive/negative/anti-double-decode/determinism probes. Does not touch
networking or reach external targets.

## Pre-release compatibility/migration notice

The result JSON schema remains `recondiff.result/v1`, and the independent
evidence candidate remains `recondiff.evidence/v1`. The correction changes
`asset_id` for some previously encoded paths, even though the JSON fields do
not change. Treat RC9 and RC10 report IDs as noninterchangeable. To upgrade,
retain and reprocess original snapshots and scope with an explicitly recorded
version; compare the original `source_*_sha256` and `scope_sha256`. Keep RC9
reports immutable as historical evidence. No ProofGraph Security IR schema or
shared adapter was silently changed.

## Deferred hard gates

Stability, supported-Go validation, hosted CI, staticcheck, govulncheck, native
macOS/Windows behavioral tests and publisher provenance remain unverified
until actually executed. No v1 or GitHub publication claim.

Primary references: RFC 3986 §§ 2.3, 6.2.2.1–2, https://www.rfc-editor.org/rfc/rfc3986.html ; Go `net/url.EscapedPath`, https://pkg.go.dev/net/url#URL.EscapedPath .
