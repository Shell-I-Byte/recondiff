> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc14 — 13 October 2026

**Release candidate, NOT stable v1.**

BUG-RD-153-001: archive sealing set every ZIP entry to `100644`, even when
Git tracks a script as `100755`. RC14 adds a signed-off **internal** executable
inventory in `SOURCE_MANIFEST_SHA256.json` and serializes ZIP modes from that
inventory. The internal manifest is hashed for consistency but it is NOT a
publisher signature. Confirmed rc13 reproduced missing executable mode; tests
cover executable/non-executable, unknown/duplicate declarations and ZIP
extract-and-reseal byte reproducibility.

`recondiff.result/v1` and `recondiff.evidence/v1` are unchanged. This is a
release metadata/portability fix, not a scanner or network feature. Native
macOS/Windows and patched Go 1.26.9/1.27.2, Staticcheck, Govulncheck and
publish/authentication gates remain open until actual executed evidence exists.

CLI `--version` is updated to `0.1.0-rc14`; result and evidence schema names are unchanged.
