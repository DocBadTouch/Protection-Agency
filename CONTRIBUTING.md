# Contributing

Start with an issue describing a parser case, detection signal, bypass, or user experience problem. Keep changes focused and explain behavior before and after.

Run `python3 -I -m unittest discover -s tests -v` from the project directory. No third-party runtime dependencies are needed. Add meaningful inert fixtures for security behavior; never retrieve or execute malware during tests.

CI runs Python 3.11–3.13 on Linux/macOS/Windows. Platform-specific POSIX terminal/mode tests and native NTFS parity tests are identified separately; skipped POSIX tests are not Windows evidence. See [validation](docs/VALIDATION.md). Use owned temporary projects/profiles and inert trusted processes; never edit a real agent profile or start a model session as a unit-test side effect. Do not weaken access-control checks to make platform tests pass.

Detection contributions must include a public source, an exact scope/version where applicable, evidence type, expected false positives, and a review action. A suspicious string is not proof of compromise. Do not add family-wide package bans when evidence only names particular releases.

Do not add target-code execution, repository-loaded plugins, unbounded reads, silent online requests, raw secret/source excerpts in results, or a fail-open safety verdict. Follow the privacy model and keep summaries compact.

Settings-edit changes need regression coverage for unrelated settings, later user edits, no-write previews, private backups, unsafe file paths/permissions, conflicts, and failures before/after replacement. Keep configuration writes in explicit setup operations. Scans/MCP must remain read-only, and diagnostics may run only reconstructed trusted guard arguments on inert events. The separate user-invoked launcher may start an explicitly selected trusted external client within its documented boundary; it is not permission to execute project code during inspection.

Keep [README.md](README.md), [Getting started](docs/GETTING-STARTED.md), [Detailed usage](docs/USAGE.md), the [CLI reference](docs/CLI.md), [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT-MODEL.md), [validation](docs/VALIDATION.md), [roadmap](docs/ROADMAP.md), [changelog](CHANGELOG.md), the [portable skill](skills/protection-agency/SKILL.md), and affected [examples](examples/) consistent with behavior changes. Keep the README focused on a newcomer completing the recommended path; put format/budget/protocol details in the reference guides. Check documented options against `python3 -I guard.py <command> --help` and verify relative links/JSON examples. Keep historical benchmark measurements tied to the version actually measured; do not relabel them as current performance. Configuration/protocol tests must never be described as verified native-client enforcement.

Onboarding changes need cancellation/EOF/nonterminal checks, explicit online consent, preview-to-write drift coverage, safe shell hints, and marker-backed evidence that refused/dry-run openings never start a client. Readable output must preserve coverage gaps and distinguish malicious-version evidence from heuristics. Do not reduce review prompts by silently approving execution. Real-client tests and newcomer usability sessions must be reported separately from local unit/terminal tests.

Agent changes must document actual native contracts, supported tools, review behavior, failure semantics, and profile/trust requirements in [the coverage matrix](docs/AGENTS-AND-PLATFORMS.md). Use distinct adapters where protocols differ. Windows changes require native ACL/junction/handle tests and safe process/PowerShell quoting checks, not only mocked POSIX results. Keep scanner/MCP policy shared across clients.

Respect original research licenses and attribution. Contributions are under this repository's MIT license. Keep creator attribution and acknowledge subsequent contributors in release notes. No CLA is required by this source checkout.
