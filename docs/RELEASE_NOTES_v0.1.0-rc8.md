> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc8 — unreleased release candidate (2026-10-10)

**No stable v1 release and no GitHub publication.** Independent offline snapshot comparison; no probes or network activity.

## Correctness/privacy changes (actually reproduced against compiled RC7)

- `BUG-RD-078-001` **FIXED:** `internal/diff/diff.go:exactSchemaKeys` reported the complete, untrusted JSON HTTP header member name via `%q` when its value was not a string. Malformed header names can embed secrets. A compiled RC7 produced secret-bearing stderr for numeric, boolean and null header values. RC8 reports only the asset index and trusted generic error. Go and offline CLI regressions cover the behavior.
- `BUG-RD-078-002` **FIXED:** `internal/diff/diff.go:strictJSON` forwarded untrusted `encoding/json` type errors. For a long numeric HTTP status, Go formatted the literal numeric token into stderr. Confirmed with a compiled RC7 and a failing unit regression. RC8 returns a content-independent typed-decoder failure, preserving rejection behavior.
- Valid same/different observations, exact JSON schema, scope, evidence digest/version, redacted security-header output, and exit codes unchanged. All test targets are synthetic `.invalid` strings; no HTTP requests are made.
- Added `internal/diff/diagnostic_privacy_test.go` and `audits/run078/synthetic_privacy_probe.py` (CI hook) with both expected failures and correct-input positive controls.

## Security and remaining gates

This is **not universal secret redaction**: filesystem paths may still appear in sanitized operational errors and other future diagnostic classes may remain unexamined. Keep case files and stderr private. The input regular-file preflight does not eliminate hostile-filesystem TOCTOU races. The repository's Git history, source manifest and SHA-256 are integrity checks, **not publisher authentication**.

Supported Go 1.26.9/1.27.2, Staticcheck v0.8.1, Govulncheck v1.8.0, real GitHub Actions and native macOS ARM64/Windows AMD64 executions are required before stable v1; do not mark a gate PASS without the actual job output. User authorization to publish a GitHub repo has not been given.
