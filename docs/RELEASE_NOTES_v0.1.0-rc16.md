> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc16 — 14 October 2026

**Release candidate, not stable v1.** BUG-RD-173-001 confirmed: RC15's
`writeAtomic` opened the entire output directory with one `O_NOFOLLOW`, which
only protects the final component; an attacker-controlled ancestor symlink was
accepted, and lexical `..` traversals were also accepted.

Proof: two negative Linux Go regressions failed against compiled RC15, while
normal nested output passed; 45 of 100 synthetic attacker-swapped writes landed
outside the intended directory (29,173 swaps). After patch, all three Go
regressions passed; 0 of 120 attempts escaped under 37,312 swaps. Subsequent
sealed-source and independent Git checks are provided separately. No external
network targets were contacted.

Fix: reject literal `..` before `filepath.Clean`, open each output directory
component with `openat` and `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` relative to a
held descriptor, preserving fd-relative temporary creation, rename, cleanup
and fsync. Legitimate absolute and relative nested directory output still works.
The evidence contracts `recondiff.result/v1` and `recondiff.evidence/v1` and
0/1/2 exit codes are unchanged. Linux native safety is qualified only for
this tested class. Underlying directory relocation, privileged mount races,
shared writable directories, native macOS/Windows runtime, patched Go toolchain,
Staticcheck, Govulncheck, hosted CI and publisher attestation remain OPEN.
No GitHub publication without permission.
