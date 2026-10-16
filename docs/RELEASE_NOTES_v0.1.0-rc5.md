> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc5 — release candidate (not certified v1)

Run052 fixed `BUG-RD-052-001`: untrusted flags, error filenames and decoded JSON error strings could spoof terminal/CI logs via newlines, ANSI escape sequences or Unicode bidi controls. Six real RC4 failures reproduced; red→green Go tests plus compiled CLI probes included. The contract `recondiff.evidence/v1` remains byte-compatible.

## Gate status

Native Linux local Go 1.23.2 suites are not supported-Go release evidence. Go 1.26.9 / 1.27.2, Staticcheck v0.8.1, Govulncheck v1.8.0 and native hosted macOS / Windows tests remain BLOCKED/UNTESTED until actually run. Public GitHub publication has **not** been authorized.
