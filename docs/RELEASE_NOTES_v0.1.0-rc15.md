> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ReconDiff v0.1.0-rc15 — 14 October 2026

**Release candidate only — not a certified stable v1.**

BUG-RD-163-001 was reproduced against compiled RC14: 33 of 200 synthetic locally attacked writes left reports outside the intended output directory when another process swapped the last directory component with a symlink. External temporary files were also observed. RC15 opens the directory with Linux `O_DIRECTORY|O_NOFOLLOW` and uses descriptor-relative `openat`, `renameat` and `unlinkat` to make the entire write/commit/cleanup path stable under that final-component swap. New Go regressions test valid output, symlink refusal, exact file permissions, replacement and absence of temporary files. A local-only independently executed adversarial CLI test is added to pinned CI.

Evidence schemas `recondiff.result/v1` and `recondiff.evidence/v1` are unchanged. Output exitcodes remain 0 (no changes), 2 (changes), 1 (error). Non-Linux output creation retains previous behavior and remains not native race-qualified. Hostile ancestor directories, mountpoints, and attackers with arbitrary ability to change the contents of a held directory are out of scope of this narrow fix. The Go 1.23.2 local toolchain is unsupported; supported Go, Staticcheck, Govulncheck and GitHub Actions results remain unverified. Publisher authentication, signed provenance and native macOS/Windows qualify as separate hard gates. No GitHub publication without operator consent.
