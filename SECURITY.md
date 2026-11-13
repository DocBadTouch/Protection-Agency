# Security policy

Protection Agency is an alpha. No release currently carries a security-support or detection guarantee.

The current source is `0.2.0a4`; it has not been published as a package/tagged release. Review [the threat model](docs/THREAT-MODEL.md) and [validation evidence](docs/VALIDATION.md) before relying on it. Host/interpreter/scanner integrity and trusted user settings remain assumptions. Native Claude loading/enforcement has not been validated, even when local configuration and trusted protocol probes pass.

For a vulnerability in this tool, use the repository's GitHub private vulnerability-reporting feature if enabled. Otherwise contact the maintainer through an established private channel and share a minimal description before exchanging sensitive details. Private reporting infrastructure is not configured by this source checkout. Do not put credentials or private code in a public issue.

For a missed detection, submit a minimal inert fixture and a public research/advisory reference. Do not submit live malware archives, active payload URLs intended to be visited, or executable exploit chains. Include the tool revision, scan level, advisory mode, platform, expected finding, and observed coverage.

Changes to filesystem access, configuration writes/backups, hook installation/removal, launch boundaries, network requests, command policy, MCP inputs, or update channels need regression tests and careful review. Scanner failures must never be translated into a clean verdict. Include the exact command, settings scope, client version when relevant, and whether the issue affects scanner output, configuration checks, or actual native-client behavior. Use owned temporary profiles and inert marker fixtures for reproductions; redact settings and backup contents because they may contain credentials.

Guided setup is an explicit settings-edit operation with terminal consent and snapshot-bound preview checks. The inert demo runs only reconstructed trusted hook arguments; its result never establishes native enforcement. The readable `open` command delegates to the existing launch gate and must not discover a project-supplied executable. Shell hints must quote all arguments and must not print terminal control sequences. These user-facing boundaries need the same review as the underlying APIs.

There is no automatic executable/rule updater or telemetry. Online scans request current eligible public dependency advisories from OSV; bundled indicators require a reviewed source upgrade. See [update behavior](README.md#does-it-update-itself), [Getting started](docs/GETTING-STARTED.md), and [the CLI reference](docs/CLI.md) for diagnostics and setup status meanings.
