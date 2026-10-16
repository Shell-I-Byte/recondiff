> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Scope and authorization

You must have permission to acquire, store and process every asset in input snapshots. The `recondiff.scope/v1` file lists complete authorized http(s) origins, e.g. `https://example.test` and states the engagement purpose. Its purpose is input filtering and documentation; it is not proof of legal authorization. `--authorized` requires a deliberate local acknowledgement. Every asset's canonical origin must match an authorized origin exactly. No wildcards, suffix matching, IP range expansion, redirects or external scanning are supported.

A surprising or mixed-origin input fails the whole comparison. Do not broaden scope by editing the scope file unless the engagement authorization genuinely permits that change. Never use this program to justify scans or exploit attempts.
