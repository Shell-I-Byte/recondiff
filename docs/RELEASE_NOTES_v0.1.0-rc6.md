> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc6 — release candidate, not stable v1

Fixes `BUG-RD-062-001` in `cmd/recondiff/main.go`: POSIX named pipes without a writer could hang input handling indefinitely before the existing bounded reader was reached. All three input slots now require regular files, and symlink-to-regular remains supported. The existing evidence schema and authorization checks are unchanged. The mitigation assumes a cooperative local filesystem; adversarial pathname replacement during open remains a documented limitation.

Qualification: Linux Go 1.23.2 is legacy and does **not** satisfy supported-toolchain evidence. Go 1.26.9/1.27.2, Staticcheck 0.8.1, Govulncheck 1.8.0, native macOS/Windows and hosted CI must be actually executed before stable v1. Do not infer native runtime from cross-compilation. GitHub publication requires explicit authorization.
