# Changelog

## 0.2.0a2 — development prerelease

- Add the user-invoked `launch` gate with a required trusted external client, isolated Python startup, no shell expansion, and dry-run receipts.
- Stop before client execution for high-priority findings, incomplete/offline advisory checks, scope gaps, invalid inputs, or failed checks. Allow explicit terminal review of at most 50 lower-priority findings when coverage is complete; no automatic or persistent approval bypass.
- Add scoped content fingerprints and a final local recheck. Reject changed selected content, Git hook mode changes, replaced project roots, ordinary client-file changes, and expired preflights. This is not an immutable snapshot or an OS sandbox.
- Inspect selected root Git configuration and hooks without running Git. Reject unsupported indirection/includes/duplicates and report known execution surfaces. Detect selected ancestor startup settings outside the chosen root.
- Sanitize known child startup injection variables, exported shell functions, Git execution overrides, and unsafe PATH entries while preserving ordinary auth/proxy/CA settings. Keep the caller's environment unchanged.
- Add 45 launch/fingerprint/environment tests, including marker-backed process checks and a real terminal approval exchange. Live vendor-client integration remains unverified.

## 0.2.0a1 — development prerelease

- Detect npm manifest/lock declaration differences, absent direct or represented transitive entries, version conflicts, and unrepresented workspaces. Handle common stable npm constraints and Python constraints against uv/Poetry lock records; unsupported syntax stays a coverage gap.
- Add explicit inventory/overall coverage state. Preserve startup parse errors across cached scans.
- Add `check_dependency` over MCP and `check-dependency` over the CLI. Checks are scoped to an exact release; online queries require explicit public registry provenance. No resolver, package manager, target import, or artifact download runs.
- Deny recognized simple install/invocation targets matching bundled malicious npm releases before scanning the project. Batch eligible proposed-release OSV queries and keep project/proposed coverage separate.
- Review project lifecycle hooks, local/remote MCP configuration, editor folder-open tasks, Python startup files, and build backends as execution surfaces. Read recognized JSON-with-comments settings without executing them.
- Retain ordinary documentation signatures as low-priority contextual findings; keep agent-instruction and executable/configuration priority.
- Add offline `doctor` diagnostics, explicitly separate from live agent enforcement verification.
- Extend regression and integration coverage and the CI platform matrix. Signed intelligence updates, a trusted pre-launch guard, artifact verification, and live-client enforcement tests remain future work.

## 0.1.0 — initial source alpha

Local scanner, npm/Python inventories, dated PolinRider indicators, opt-in OSV checks, MCP stdio server, conservative Claude Bash hooks, portable skill, and 30 passing tests. Published on GitHub under DocBadTouch with an MIT license.
