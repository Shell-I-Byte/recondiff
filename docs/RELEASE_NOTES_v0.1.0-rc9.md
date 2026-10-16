> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc9 — unreleased release candidate (2026-10-10)

Fixes `BUG-RD-086-001` (confirmed local file availability/TOCTOU bug). The RC8 CLI could hang indefinitely when another local process atomically exchanged a regular input file for an unwritten FIFO between the `os.Stat` preflight and `os.Open`. On Linux/macOS RC9 opens nonblocking and checks the opened descriptor; Windows/other OS retains the original limited fallback. A synthetic adversarial swap and direct FIFO/symlink/directory controls are included. No new scanning/network capability or schema change. Native macOS/Windows runtime and supported Go analyzer tests remain pending. SHA-256 manifests are consistency checks, not authenticated publisher signatures.
