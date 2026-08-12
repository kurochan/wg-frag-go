# Security policy

wg-frag-go is experimental software and is provided without warranty. Security
reports are handled on a best-effort basis; there is no guaranteed response
time, availability target, or commitment to issue a fix.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository:

<https://github.com/kurochan/wg-frag-go/security/advisories/new>

Do not include sensitive vulnerability details in a public issue or pull
request. If private reporting is unavailable, open an issue without the
technical details and ask for a private reporting channel.

Include the affected commit or version, operating system and architecture,
configuration needed to reproduce the issue, and the smallest safe
reproduction. Remove private keys, endpoints, hostnames, and other sensitive
data from reports.

The latest tagged release, when available, and the `main` branch are the
intended review targets. Older versions may not receive fixes.

## Scope

The security boundary and known non-goals are documented in
[`docs/threat-model.md`](docs/threat-model.md). In particular, root access,
the kernel, the WireGuard process, private keys, and cryptographic primitives
are trusted boundaries. Availability degradation caused by a configured,
authenticated peer is a documented residual risk.
