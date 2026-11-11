# Threat model and limits

Protection Agency helps a developer inspect an untrusted project before an agent installs, imports, builds, or tests it. It also surfaces known dependency advisories that could affect shipped software. It is an alpha screening tool, not endpoint protection, a semantic auditor, or a complete software supply-chain security platform.

## Trust assumptions

The host, Python interpreter, scanner checkout, and user-level agent settings are trusted. The inspected repository, dependency metadata, package scripts, agent instructions, tool output, and remote advisory responses are untrusted. Keep the scanner and hook settings outside the inspected repository. A user with permission to modify the scanner or disable the hook can remove its protection.

No project package managers, build backends, Git hooks, imports, or tests are invoked by a scan. Symlink file reads and special files are refused. The scanner still parses attacker-controlled files inside the current Python process. File limits and bounded patterns reduce resource exposure; run it in a resource-limited process/container when inspecting hostile repositories. Traversal and network deadlines are cooperative, not a hard CPU or wall-clock kill.

## Coverage

Supported inventories do not prove they match an installed tree or current manifest. Lockfile freshness, package integrity verification against registry artifacts, package provenance attestations, dependency reachability, environment selection, and SBOM generation are not implemented. The presence of an integrity field is checked, but its hash is not verified. All represented lock entries are considered, including development and environment-specific dependencies.

`requirements*.txt`/`.in` accept exact pins only, with simple extras, markers, and hashes. Includes, constraints, editable paths, ranges, direct URLs, and index directives are reported as gaps and not followed. `pyproject.toml` only handles exact static PEP 621 pins. Dynamic dependencies and Poetry manifests require further review. `uv.lock` and `poetry.lock` supply a wider inventory, without resolving packages. npm lockfiles v1, pnpm, Yarn, Bun, PDM, Pipenv, and setup.py/setup.cfg dependency execution are unsupported and reported when encountered.

Quick scope does not inspect all application code. Standard scope excludes installed and generated directories; deep includes them under the workspace and the same budgets. Git metadata, cache directories, `.env*`, private-key file extensions, arbitrary binaries, non-UTF8 data, and unknown file extensions are not analyzed as source. Unicode tricks, computed imports, indirect execution, staged downloads, sophisticated obfuscation, prompt injection, vulnerable business logic, zero days, and malware absent from available intelligence may evade detection. A documentation example can trigger the same signature as a loader.

## Privacy and intelligence

Offline scans make no network calls. Online scans send eligible public package names, versions, and ecosystems to the fixed OSV endpoint. They do not send source, absolute project paths, scripts, tokens, or lockfile contents. The service, proxy operator, and network infrastructure can observe those queries.

Source classification uses recorded inventory URLs and project `.npmrc` registry declarations. Unknown/private sources are omitted and reported. Plain requirements pins assume default PyPI in the absence of source directives. User/global package manager configuration, DNS policy, environment-specific index overrides, and registry credentials are not resolved. If a package name is confidential or its source uncertain, keep online mode off. This is not a promise that every private name can be inferred from arbitrary manifests.

The embedded IOC snapshot is small, version-specific, and dated. OSV coverage depends on upstream advisory ingestion; emerging attacks may not be listed. Failed requests, pagination limits, or skipped packages result in incomplete coverage. A zero-match result covers only the exact checked versions at the reported time. No background polling or incident alerting is implemented.

## Enforcement boundaries

An MCP tool acts only when called. A skill can be ignored or manipulated. The Claude adapter handles Bash only and requires correct trusted installation. SessionStart only contributes context. The pre-execution hook denies selected patterns and requests human review for other execution; it does not run or sandbox the command itself.

Unsupported execution tools, alternative MCP servers, IDE extensions and autorun before the agent starts, shell startup files, another terminal, disabled hooks, client bugs, and approved commands remain outside this adapter. Project edits may race a check. User review does not make unknown code trustworthy. Use OS isolation, restricted network access, and minimal credentials for execution.

This project does not certify that a machine is uncompromised, recover stolen credentials, or make vulnerable software safe for end users. An already-compromised host can interfere with any local scanner. Prior malicious execution requires incident investigation outside this tool.
