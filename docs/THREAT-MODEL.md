# Threat model and limits

Protection Agency helps a developer inspect an untrusted project before an agent installs, imports, builds, or tests it. It also surfaces known dependency advisories that could affect shipped software. It is an alpha screening tool, not endpoint protection, a semantic auditor, or a complete software supply-chain security platform.

## Trust assumptions

The host, Python interpreter, scanner checkout, and user-level agent settings are trusted. The inspected repository, dependency metadata, package scripts, agent instructions, tool output, and remote advisory responses are untrusted. Keep the scanner and hook settings outside the inspected repository. A user with permission to modify the scanner or disable the hook can remove its protection.

No project package managers, build backends, Git hooks, imports, or tests are invoked by a scan. Symlink file reads and special files are refused. The scanner still parses attacker-controlled files inside the current Python process. File limits and bounded patterns reduce resource exposure; run it in a resource-limited process/container when inspecting hostile repositories. Traversal and network deadlines are cooperative, not a hard CPU or wall-clock kill.

## Coverage

Supported inventories do not prove they match an installed tree. Basic npm declaration/entry consistency and common stable-version constraints are checked, including represented transitive declarations and workspace records. This is a supported subset, not full package-manager resolution or synchronization validation. Full lockfile freshness, artifact integrity verification, provenance attestations, dependency reachability, environment selection, and SBOM generation are not implemented. The presence of an integrity field is checked, but its hash is not verified. All represented lock entries are considered, including development and environment-specific dependencies.

`requirements*.txt`/`.in` accept exact pins only, with simple extras, markers, and hashes. Includes, constraints, editable paths, ranges, direct URLs, and index directives are reported as gaps and not followed. Static PEP 621 declarations and simple dependency groups are checked against supported sibling Python locks. Stable numeric comparisons, npm full-version caret/tilde/comparators/disjunctions, and Python numeric comparators/compatible-release constraints are supported. Prerelease ordering, wildcard/partial npm selectors, environmental marker evaluation, direct-source resolution, and other syntax require review. Dynamic dependency metadata and Poetry-specific manifests require separate review. `uv.lock` and `poetry.lock` supply a wider inventory without resolving packages. npm lockfiles v1, pnpm, Yarn, Bun, PDM, Pipenv, and setup.py/setup.cfg dependency execution are unsupported and reported when encountered.

Proposed-dependency checks inspect an exact release identity, not the resolved graph or package bytes. The command adapter recognizes a limited set of simple install/invocation forms, with up to 32 extracted targets. It does not evaluate wrappers, expansions, requirements files, arbitrary command syntax, or every package-manager option. Those commands remain review cases. Online proposed-target queries additionally require explicit public registry provenance; unknown options and extra indexes suppress those queries. A bundled malicious identity is a published name/version match, not proof that bytes in a private registry are identical.

Quick scope does not inspect all application code. Standard scope includes quick-selected files and recognized project text; deep adds installed/generated directories under the same budgets. Selected execution surfaces include project agent hooks, MCP commands/URLs, editor folder-open tasks, `.pth` imports, Python startup modules, and native/Python build configuration. They are reviewed as configuration, not automatically classified as malware. Malformed or over-budget recognized configuration produces a gap. Ordinary Markdown/reStructuredText and selected README-like text files retain low-priority documentation indicators; agent instructions and configuration retain normal priority. Context is a filename-based heuristic, not proof that a file cannot execute.

Git metadata, cache directories, `.env*`, private-key extensions, arbitrary binaries, non-UTF8 data, and unknown extensions are outside source scope. Unicode tricks, computed imports, indirect execution, staged downloads, sophisticated obfuscation, prompt injection, business-logic vulnerabilities, zero days, and malware absent from available intelligence may evade detection.

## Privacy and intelligence

Offline scans make no network calls. Online scans send eligible public package names, versions, and ecosystems to the fixed OSV endpoint. They do not send source, absolute project paths, scripts, tokens, or lockfile contents. The service, proxy operator, and network infrastructure can observe those queries.

Source classification uses recorded inventory URLs and project `.npmrc` registry declarations. Unknown/private sources are omitted and reported. Plain requirements pins assume default PyPI in the absence of source directives. User/global package manager configuration, DNS policy, environment-specific index overrides, and registry credentials are not resolved. If a package name is confidential or its source uncertain, keep online mode off. This is not a promise that every private name can be inferred from arbitrary manifests.

The embedded IOC snapshot is small, version-specific, and dated. OSV coverage depends on upstream advisory ingestion; emerging attacks may not be listed. Failed requests, pagination limits, or skipped packages result in incomplete coverage. A zero-match result covers only the exact checked versions at the reported time. No background polling or incident alerting is implemented.

## Enforcement boundaries

An MCP tool acts only when called. A skill can be ignored or manipulated. The Claude adapter handles Bash only and requires correct trusted installation. SessionStart only contributes context. The pre-execution hook denies selected patterns and requests human review for other execution; it does not run or sandbox the command itself.

Startup-configuration findings do not stop lifecycle hooks that run before or alongside this adapter. A trusted pre-launch enforcement layer is not implemented in this prerelease. `doctor` performs offline scanner self-checks and explicitly reports live client enforcement as unverified. It does not inspect or certify installed agent configuration.

Unsupported execution tools, alternative MCP servers, IDE extensions and autorun before the agent starts, shell startup files, another terminal, disabled hooks, client bugs, and approved commands remain outside this adapter. Project edits may race a check. User review does not make unknown code trustworthy. Use OS isolation, restricted network access, and minimal credentials for execution.

This project does not certify that a machine is uncompromised, recover stolen credentials, or make vulnerable software safe for end users. An already-compromised host can interfere with any local scanner. Prior malicious execution requires incident investigation outside this tool.
