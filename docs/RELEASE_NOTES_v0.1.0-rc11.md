> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc11 — local release candidate — 12 October 2026

**Status:** tested on Linux AMD64 with local Go 1.23.2; **not a stable v1 release**. No independent native Windows/macOS test, supported-Go CI, Staticcheck or Govulncheck success claimed.

## Material fix: JSON Schema integer status interoperability

`schema/recondiff-snapshot-v1.schema.json` declares status as an `integer` between 100 and 599. A Go `int` field in the v1 JSON decoder wrongly rejected syntactically valid equivalent JSON numbers such as `200.0`, `2e2` and `5.99e2`. The parser now checks exact decimal mathematical value; a value such as `200.00000000000000000001` is NOT rounded to 200. New targeted Go and independent synthetic CLI regressions cover positive, negative and exponent/precision boundaries. Official semantics: https://json-schema.org/draft/2020-12/draft-bhutton-json-schema-validation-01#section-6.1.1 .

The released evidence schema and asset identifiers are unchanged. All input SHA-256 fields still cover exact bytes and can differ across numerically equivalent JSON spellings. No ProofGraph promotion of unverified evidence is authorized. Versions prior to rc11 can have falsely rejected valid snapshot inputs and should be replayed from preserved originals.

## Residual release gates

Supported Go versions, Staticcheck, Govulncheck, native macOS/Windows, hosted CI success and publisher authentication remain BLOCKED/UNTESTED/UNVERIFIED. See `audits/run123/OPEN.json`.
