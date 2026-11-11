# Security policy

Protection Agency is an alpha. No release currently carries a security-support or detection guarantee.

For a vulnerability in this tool, use the repository's GitHub private vulnerability-reporting feature if enabled. Otherwise contact the maintainer through an established private channel and share a minimal description before exchanging sensitive details. Private reporting infrastructure is not configured by this source checkout. Do not put credentials or private code in a public issue.

For a missed detection, submit a minimal inert fixture and a public research/advisory reference. Do not submit live malware archives, active payload URLs intended to be visited, or executable exploit chains. Include the tool revision, scan level, advisory mode, platform, expected finding, and observed coverage.

Changes to filesystem access, network requests, command policy, MCP inputs, or update channels need regression tests and careful review. Scanner failures must never be translated into a clean verdict.
