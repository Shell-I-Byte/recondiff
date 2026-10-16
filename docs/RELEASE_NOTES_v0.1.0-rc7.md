> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc7 — unreleased release candidate (2026-10-10)

- Fixed `BUG-RD-071-001`: malformed offline snapshot/scope JSON could place private string tokens or attacker-controlled member keys in terminal/CI diagnostics. RC6 reproduced four failing Go regressions and a compiled-CLI leakage example. RC7 replaces diagnostics for trailing JSON tokens, duplicate member names and unexpected member names with content-independent errors. Valid evidence input and all `recondiff.evidence/v1` output remain unchanged.
- New Go regressions (`cmd/recondiff/privacy_diagnostic_test.go`) and independent offline black-box Python probe (`audits/run071/malformed_diagnostic_probe.py`) run under pinned CI when published.
- Not a universal secret-redaction guarantee: filesystem path diagnostics and operational logs remain private. Run in trusted local case workspace.
- Stable v1 is blocked pending tests with supported Go 1.26.9/1.27.2, Staticcheck, Govulncheck, native macOS/Windows and observed hosted CI; no GitHub publication permission supplied.
