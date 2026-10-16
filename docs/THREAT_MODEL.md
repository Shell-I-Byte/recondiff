> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Threat model (v0.1.0-rc10)

Assume JSON snapshots may be malformed or attacker-controlled. Threats: unauthorized out-of-scope observations, parser ambiguity (duplicates), oversized input, ambiguous URL normalization, credentials in query/headers/path, accidental report over-disclosure, non-deterministic evidence and partial report writes. Controls: required explicit scope and CLI acknowledgement, strict JSON, hard limits, fail-closed validation, sensitive URL fields dropped, only SHA-256 digests of enumerated security header values, path never echoed, canonical SHA-256 asset IDs, deterministic ordered JSON, 0600 atomic files, I/O errors signaled. Scope file is a claim, **not** cryptographically verified authorization: analysts remain accountable for permission and provenance.

Known limitations: hashing low-entropy header values is not confidentiality (guessable by an adversary); reports can still reveal domains, response codes and change patterns. Do not share with unauthorized parties. The tool cannot establish that a vulnerability exists or whether a missing header is exploitable. It cannot validate the truth of input snapshots. It does not validate live certificate chains or perform network I/O. Zero-value timestamp means no temporal provenance; source hashes bind exact bytes but the snapshot schema does not authenticate the collector. Preserve original inputs in your secured case management system. Library or CI secrets must not be embedded in examples.

## Run052 diagnostic injection boundary

Local attackers with control of CLI argument bytes, evidence filenames or invalid JSON text previously could cause terminal/CI stderr spoofing. The CLI now suppresses raw parser diagnostics, emits a constant error for malformed flags, and ASCII-quotes all dynamic error strings. No data is sent to remote endpoints, and evidence-output semantics are unchanged. Privacy boundary does not extend to full semantic secret detection in error strings. This regression is exercised using deliberately malformed local fixtures, not external targets.

## Run062 bounded file-input contract

A named pipe with no writer previously blocked `os.Open` before byte limits were applied. RC6 rejects nonregular snapshot/scope inputs before opening and validates the descriptor after opening. Symlink-to-regular paths remain accepted. Since standard portable Go file-opening APIs do not perform an atomic mode-test-plus-open, hostile concurrent filesystem replacement is not fully prevented. The CLI remains an offline analyst utility and should execute inside a trusted filesystem workspace.

## Run071 malformed JSON secret-token disclosure fix

Trailing JSON tokens and unknown/duplicate object member names must not be
formatted into error messages. Previously, `safeDiagnostic` escaped control
characters yet still emitted literal token content. RC7 uses constant
messages for these parser branches and includes a synthetic black-box guard.
Other diagnostics may still contain filesystem path information; stderr is
private operational evidence, **not a fully sanitized public log**.


### Run078 — malformed typed JSON diagnostics

Malformed per-header JSON values previously included attacker-controlled header
keys in error text; malformed enormous numeric status values could be included
by the Go JSON decoder's type errors. RC8 replaces these two paths with static
diagnostics; local compiled RC7 reproduction and RC8 regressions are recorded
in `audits/run078/`. This does **not** prove complete operational-log privacy: 
filenames and unrelated future parser errors remain a known privacy boundary.

## Run086 — nonblocking descriptor-open for Unix

A local process with directory write access can atomically replace a regular
input with an unwritten FIFO between the prior pathname check and `os.Open`,
causing an indefinite hang. RC9 uses `O_NONBLOCK|O_CLOEXEC` on Linux and macOS
and validates the opened descriptor. The fix prevents the reproduced FIFO-open
hang but does not authenticate the input file, defend against all malicious
filesystem replacements (including regular-to-regular swaps), prevent remote
filesystem stalls, or establish a Windows guarantee. Avoid adversarial shared
case directories. Native macOS and Windows tests are still required.

## Run096 — URI-percent-equivalence evidence accuracy

RC9 incorrectly treated equivalent percent-encoding variants as different
assets. RC10 normalizes the ASCII unreserved set and uppercase triplet hex while
retaining reserved escapes; it does NOT interpret/dereference resources or
remove dot segments. Different web servers may perform extra path rewrites;
ReconDiff must not guess server-specific semantics. The corrected hash can
change asset IDs relative to earlier RC snapshots; retain raw input evidence
and replay with a pinned version, not join evidence across RC versions by ID.

Run134: HTTP field names are validated with RFC 9110 token grammar (ASCII `tchar`); invalid whitespace, separators or Unicode keys are rejected before deciding whether a field belongs to the selected security-header allowlist. This prevents malformed input from silently erasing an apparent security-header change. Offline snapshots remain untrusted claims, not live HTTP proof.

## Run173 — Linux ancestor-directory symlink and lexical parent traversal

RC15 used `O_NOFOLLOW` only on the final output-directory component: a symlink
at an earlier component could redirect private reports outside the chosen tree.
RC16 rejects literal `..` before path cleaning and opens every output directory
component with a directory descriptor and `O_NOFOLLOW`, then uses the held fd
for exclusive temporary creation, replacement, cleanup and directory syncing.
A local-only concurrent attacker reproduced 45 escaped reports in 100 RC15
requests, versus zero escapes in 120 RC16 requests. This does not protect
against privileged mount changes, malicious modification of the contents of
already-open directories, or moving already-open directory inodes out of the
original tree. macOS and Windows fallbacks remain explicitly unqualified.
