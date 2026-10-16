> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc12 — candidate, NOT stable v1

- **BUG-RD-134-001 fixed:** before RC12 an invalid HTTP field name such as `X-Frame-Options ` (trailing space) was silently ignored rather than rejected, allowing a false negative in an otherwise identical offline comparison. RFC 9110 §5.1 requires a field-name to be a `token` (ASCII `tchar` only). A malformed snapshot now fails closed with input error exit 1. The change also validates ignored/non-allowlisted fields. Regression controls include positive legal punctuation and negative whitespace/separators/Unicode cases, plus independent CLI replay and no-leak assertions.
- `schema/recondiff-snapshot-v1.schema.json` now requires RFC token property names to match actual runtime acceptance. JSON result schema and `recondiff.evidence/v1` are unchanged.
- CI Govulncheck pin updated from v1.8.0 to v1.9.0; no analyzer or supported Go CI success is claimed.
- Source SHA manifest and sealed source ZIP must be regenerated after checkout; this RC must be tested from the ZIP and independent Git clone. Native macOS and Windows are NOT yet qualified.
