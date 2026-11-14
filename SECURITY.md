# Security policy

Protection Agency is an alpha. No release currently carries a security-support or detection guarantee.

The current source is `0.3.0a1`; it has not been published as a package/tagged release. Review [the threat model](docs/THREAT-MODEL.md), [agent/platform scope](docs/AGENTS-AND-PLATFORMS.md), and [validation](docs/VALIDATION.md). Host/interpreter/scanner integrity and trusted user settings remain assumptions. Native Codex/Claude loading/enforcement is unverified even when local probes pass. Windows support is experimental and restricted to local fixed NTFS.

For a vulnerability in this tool, use the repository's GitHub private vulnerability-reporting feature if enabled. Otherwise contact the maintainer through an established private channel and share a minimal description before exchanging sensitive details. Private reporting infrastructure is not configured by this source checkout. Do not put credentials or private code in a public issue.

For a missed detection, submit a minimal inert fixture and a public research/advisory reference. Do not submit live malware archives, active payload URLs intended to be visited, or executable exploit chains. Include the tool revision, scan level, advisory mode, platform, expected finding, and observed coverage.

Changes to filesystem access, configuration writes/backups, hook installation/removal, launch boundaries, network requests, command policy, MCP inputs, or update channels need regression tests and careful review. Scanner failures must never be translated into a clean verdict. Include the exact command, settings scope, client version when relevant, and whether the issue affects scanner output, configuration checks, or actual native-client behavior. Use owned temporary profiles and inert marker fixtures for reproductions; redact settings and backup contents because they may contain credentials.

Guided setup is an explicit settings-edit operation with terminal consent and snapshot-bound checks. Demos invoke trusted adapter arguments only. Native Windows uses reparse refusal, handle-relative operations, owner/DACL validation, private backups, and native locks; unsupported ACLs/paths must not fall back to ordinary writes. Owner-rights ACL entries apply only after validating the owner. The before-start gate must not discover project executables; Windows batch clients are refused. Review relay quoting and all native API structure/access assumptions. Neither platform backend supplies runtime isolation.

The Codex adapter deliberately denies review-needed commands because native hook `ask` is unsupported. Its local check errors emit denials, but native startup/timeouts can continue. Native trust is never bypassed automatically. Report native behavior separately from scanner/protocol results; no adapter may claim universal interception of other execution tools.

There is no automatic executable/rule updater or telemetry. Online scans request current eligible public dependency advisories from OSV; bundled indicators require a reviewed source upgrade. See [update behavior](README.md#does-it-update-itself), [Getting started](docs/GETTING-STARTED.md), and [the CLI reference](docs/CLI.md) for diagnostics and setup status meanings.
