# Contributing

Start with an issue describing a parser case, detection signal, bypass, or user experience problem. Keep changes focused and explain behavior before and after.

Run `python3 -I -m unittest discover -s tests -v` from the project directory. No third-party runtime dependencies are needed. Add meaningful inert fixtures for security behavior; never retrieve or execute malware during tests.

Detection contributions must include a public source, an exact scope/version where applicable, evidence type, expected false positives, and a review action. A suspicious string is not proof of compromise. Do not add family-wide package bans when evidence only names particular releases.

Do not add target-code execution, repository-loaded plugins, unbounded reads, silent online requests, raw secret/source excerpts in results, or a fail-open safety verdict. Follow the privacy model and keep summaries compact.

Respect original research licenses and attribution. Contributions are under this repository's MIT license. Keep creator attribution and acknowledge subsequent contributors in release notes. No CLA is required by this source checkout.
