> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Architecture

- `cmd/recondiff`: flags, local reads, explicit authorization acknowledgement, exit codes, atomic 0600 report writes.
- `internal/diff`: recursive duplicate JSON-member rejection, strict decoding, size and count guards, authorized origin checks, URL canonicalization (scheme, host, default ports, path), security-header digesting, deterministic ordered change detection.
- `schema`: versioned JSON data shape contracts; Go decoder enforces additional tighter semantic constraints.
- `examples`: fabricated `.test` domains and local loopback addresses. No scanners/transports in this project.

Input size is limited to 4 MiB per file; a snapshot has at most 10,000 assets, 128 headers per asset and 2,048 bytes per header value. No data is sent to external services. All comparisons operate on observations, not assertions of exploitable vulnerability. No attack path, exploit or red-team execution capability.

**Domain support:** ASCII hostname labels, IPv4, bracketed IPv6, Punycode A-labels for IDNs; other Unicode hostnames rejected until an independently validated IDNA implementation exists. A URL may include query input but it is ignored for canonical identity; credentials are rejected. Redirects, TLS validity, cookies and request timing are out-of-scope for this offline-only comparison tool.
