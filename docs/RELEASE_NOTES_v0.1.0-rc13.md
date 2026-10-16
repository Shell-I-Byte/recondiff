> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc13 — 13 October 2026

**Release candidate only; not a qualified stable v1.**

BUG-RD-145-001 (MEDIUM): RC12 compared asset identity paths without removing
RFC 3986 dot segments, producing false `added` + `removed` changes for the same
resource. It also allowed equivalent normalized paths in one snapshot to be
counted separately. Confirmed by pre-fix failing Go tests and compiled RC12
CLI (exit 2 instead of exit 0).

Fix: RFC 3986 §5.2.4 dot-segment removal after unreserved percent-decoding.
Positive/negative regression tests preserve double slashes, `%2F`, escaped
percent, case-sensitive path segments and trailing slash semantics.

**Migration notice:** the IDs of affected resources may change; old RC12
reports cannot be equated to RC13 by copying IDs. Reprocess preserved original
snapshot files. Wire shape and names (`recondiff.result/v1`,
`recondiff.evidence/v1`) remain unchanged, but neither is certified stable.
Source hashes are still SHA-256 of the exact original JSON bytes.

No scanner/network capability added. Supported Go branches 1.26.9/1.27.2,
Staticcheck, Govulncheck, hosted CI and native macOS/Windows remain release
blockers until actual evidence is collected.
