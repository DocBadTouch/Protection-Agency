# Protection Agency

**Your agent needs an agency.**

Local security screening for coding agents, created by [DocBadTouch](https://github.com/DocBadTouch). Check projects before running them, surface known vulnerable or malicious dependency versions, and put review in front of risky execution.

**Status: working alpha, not a security boundary or a guarantee of safety.** It combines a command-line scanner, a small MCP stdio server, a Claude Code hook adapter, and a portable agent skill. No LLM calls. No third-party runtime dependencies. Python 3.11+ on Linux/macOS.

The `0.2.0a1` development prerelease adds proposed-dependency checks, inventory consistency checks, startup-configuration review, documentation context, and offline diagnostics. See [the changelog](CHANGELOG.md).

The `0.2.0a2` development prerelease adds a user-invoked **pre-launch gate**: inspect first, stop on incomplete/high-priority results, optionally review lower-priority findings, recheck selected content, then start an explicitly chosen trusted client. It does not provide a sandbox.

## What works today

- Read npm lockfiles v2/v3, npm shrinkwrap, exact npm manifest pins, `uv.lock`, `poetry.lock`, exact Python requirements pins, and exact PEP 621 manifest pins.
- Check represented npm direct/transitive entries and manifest declarations, plus common stable-version Python constraints against supported locks. Missing, conflicting, and unsupported declarations remain coverage gaps.
- Check proposed exact npm/PyPI releases through the CLI or MCP before installation. The Bash adapter denies recognized installs of bundled known-malicious npm releases even when they are absent from the project.
- Flag exact published PolinRider npm releases from a dated, attributed intelligence snapshot.
- Detect selected encoded execution patterns, download-to-shell commands, suspicious instructions, editor autorun tasks, and lifecycle scripts. These are review signals; benign examples can match.
- Optionally query [OSV](https://osv.dev/) for current version-specific advisories, including `MAL-*` malicious-package records. Generic advisories request review; they are not automatically labeled critical.
- Scan without installing dependencies, running scripts, importing project modules, invoking Git, or loading project plugins.
- Return compact summaries; retrieve details only when needed. Cache static findings by file-content hash in the MCP process.
- Provide Claude `SessionStart` context and a conservative `PreToolUse` Bash gate.
- Inventory selected project hooks, MCP launch configurations, editor autorun tasks, Python `.pth`/startup modules, and native/Python build configuration without starting any of them. Common JSON comments and trailing commas are supported in recognized startup settings.
- Keep signatures in documentation visible as low-priority review findings. Agent instructions and executable/configuration files retain their normal priority.

## Start without installing packages

Keep the scanner in a trusted location **outside the project you are inspecting**. Review its source first. It is itself trusted executable code.

```bash
python3 -I /trusted/protection-agency/guard.py scan /path/to/project
python3 -I /trusted/protection-agency/guard.py scan /path/to/project --online
python3 -I /trusted/protection-agency/guard.py scan /path/to/project --level deep --online --full
python3 -I /trusted/protection-agency/guard.py doctor --root /path/to/project
```

`-I` isolates Python startup from project paths and Python environment overrides. The launcher adds only its own trusted `src` directory. No `pip install` is required. Distribution metadata is provided for future packaging; this project has not yet been released on PyPI or npm.

Offline is the default. `--online` opts in to sending eligible **package names, ecosystems, and versions** to `https://api.osv.dev/v1/querybatch`. Source files, scripts, credentials, and project paths are not sent. Requests use normal system TLS and proxy settings; redirects are refused.

Registry-backed npm/uv/Poetry entries are eligible when their recorded source is a recognized public registry. Manifest-only pins have unresolved provenance and are omitted from OSV. Plain requirements pins assume PyPI unless a custom source directive is present. Environment-wide package-manager configuration is not resolved: use offline mode for confidential inventories. See [privacy and coverage](docs/THREAT-MODEL.md).

| Level | Source scope | Typical use |
| --- | --- | --- |
| `quick` | Inventories, agent instructions, editor/agent settings, selected configuration | Initial triage |
| `standard` | Above plus recognized project text/source extensions | Start of work; default |
| `deep` | Above plus recognized text in installed dependencies and generated directories | After a controlled install; wider review |

All levels can query the same dependency inventories with `--online`. “Deep” adds source coverage; it is not a sandbox or a full semantic code audit. No level installs or downloads package artifacts.

Defaults cap scans at 5,000 selected files, 40,000 traversed entries, 32 MiB of input, 1 MiB per ordinary file, and 8 MiB per inventory. Static work has a 20-second cooperative budget; OSV has a separate 25-second budget. Those budgets bound ordinary work; they are not process-enforced CPU/memory isolation. Gaps appear in the result. `.git`, caches, secrets such as `.env`/private key files, binaries, and unrecognized extensions are outside the source scope. Symlinks are refused and reported.

| Result | Meaning | Scan exit code |
| --- | --- | --- |
| `no_findings` | No matches in the requested scope; advisory lookup completed | `0` |
| `block` | High-priority suspicious pattern or known malicious release; pause execution | `1` |
| `review` | Review signals, omitted checks, offline advisories, or incomplete coverage | `2` |
| Check error | The check could not complete | `3` |

`no_findings` never means “safe.” Offline results require review because current advisories were not checked. High-priority pattern matches can be benign examples or research code; inspect evidence before drawing an incident conclusion.

Coverage separately reports `inventory` (`complete`, `incomplete`, or `not_present`), advisory state, gaps, and a `complete` boolean for the requested scan scope. Complete coverage can still contain findings. Checks cover a documented subset of declaration syntax; they do not reproduce a package manager's resolver or verify installed artifacts.

## Check a proposed dependency

```bash
python3 -I /trusted/protection-agency/guard.py check-dependency npm cdeops 13.5.31
python3 -I /trusted/protection-agency/guard.py check-dependency PyPI requests 2.32.0 --registry https://pypi.org/simple --online
```

The first example checks inert release metadata and exits `1` because the bundled research identifies that release. Neither example installs or downloads a package artifact. Proposed versions must be exact supported releases for an OSV lookup; ranges, tags, and missing versions remain unresolved review cases. Explicit public registry provenance and `--online` are both required to send a proposed identity to OSV. Registry URLs are classified locally; the only request destination is OSV. Private, unspecified, credential-bearing, or unsupported registry URLs are not queried.

`check-dependency` covers **one exact release**, with transitive packages and artifact contents explicitly outside its scope. A zero-match result is limited to that release and lookup time. It does not authorize installation or imply the dependency graph is safe.

The command adapter recognizes simple npm/pnpm/yarn/bun install/add commands, npx/bunx invocation targets, pip installs (including `python -m pip` and `uv pip`), and uv/Poetry add commands. It extracts at most 32 targets, never follows requirements files or evaluates shell syntax, and keeps unsupported commands subject to review. Known malicious exact npm identities are denied offline. Eligible proposed releases use a batched OSV check with one shared network budget when online mode and explicit public registry options are present. Extra indexes and unknown options suppress proposed-target queries. This adapter is not a complete shell or package-manager parser.

## Verify scanner diagnostics

`doctor` runs six offline checks of the runtime, secure file-reading support, known malicious install classification, documentation context, startup configuration, and missing lock entries. It also warns about a scanner installed inside the target root or Python startup without isolation. Its exit code is `0` for passing self-checks and `1` for failed self-checks; invalid roots produce the ordinary check-error exit code `3`.

**Doctor does not certify that a live client has installed or enforced the hook.** It reports `live_client_enforcement: not_verified`. Verify the actual client, hook order, failure behavior, and sandbox separately before relying on them.

## Gate agent startup before the client starts

Use a trusted scanner installation outside the inspected project and an already installed, trusted client executable outside that project. Python `-I` and an absolute executable path are required. Separate client arguments with `--`:

```bash
python3 -I /trusted/protection-agency/guard.py launch --online --dry-run /path/to/project -- /absolute/path/to/claude
python3 -I /trusted/protection-agency/guard.py launch --online /path/to/project -- /absolute/path/to/claude
python3 -I /trusted/protection-agency/guard.py launch --online --review /path/to/project -- /absolute/path/to/claude
```

These examples name a client; the launcher does not download or install it. `--dry-run` prints a preflight receipt and never starts a client. A later real launch always inspects again. Normal launch emits preflight JSON on stderr and leaves the client's stdout/stdin available for normal use. Child arguments are passed directly with `shell=False`, without shell expansion.

The gate runs a standard project scan plus a bounded inspection of selected Git startup metadata. By default, findings requiring review stop the launch. `--review` permits a one-time, randomly generated terminal challenge for **at most 50 lower-priority findings**, only when requested coverage and advisories completed. It displays all reviewable finding metadata before the challenge. Piped approval, an automatic yes flag, saved approval receipts, high-priority findings, incomplete/offline advisory checks, and coverage gaps cannot authorize a launch. This is an explicit caller review step, not proof that the project is safe or that the terminal operator is human.

Before starting the client, the launcher rereads selected project content and Git metadata, compares fingerprints and static findings, and checks project-directory/client-file identity. Source edits, added startup files, changed Git hook permissions, root replacement, ordinary executable changes, or a preflight older than five minutes stop the launch. Fingerprints cover the declared scope. They do not freeze the filesystem, verify all client dependencies, or prevent changes after the final check.

The launch-only Git check reads a regular root `.git/config` (up to 256 KiB) and up to 128 hook-directory entries (64 KiB per inspected non-sample file). Known executable helpers and executable hooks require review. Symlinks, indirect/shared Git directories, per-worktree configuration, custom hook paths, config includes, ambiguous duplicate Git configuration, and unreadable/over-budget metadata produce coverage gaps. Git itself and its hooks are never run during inspection. Normal scans continue to exclude Git metadata.

Known agent/editor startup settings above the selected root also produce a gap; select the intended project root that includes them. User-home and other trusted global/client configuration remain part of the trusted setup. Additional client workspaces or arbitrary configuration paths supplied in client arguments need separate review; this generic launcher does not reproduce every client's settings precedence.

The child environment removes known interpreter/shell/dynamic-loader injection variables, exported Bash functions, and known Git executable overrides. `PATH` keeps only existing absolute directories outside the project. Known executable Git environment-config entries are removed while remaining transport/auth entries keep their values. Proxy, CA trust, authentication, and other ordinary environment values are preserved; values and client arguments are not printed. Global configuration environment paths cannot point inside the project or be relative. Sanitization affects only the child environment and is not a credential or process sandbox.

Before any client starts, guard exits are `1` for high-priority findings, `2` for review/incomplete/changed/expired checks, `3` for check/start errors, and `130` for interruption. Once a client runs, its exit status is returned, so those codes can overlap client exit codes; the preflight's `execution` field distinguishes the phases.

**The running client is not isolated by this launcher.** Use an appropriate OS/client sandbox, minimal credentials, and runtime permissions. This gate cannot undo IDE startup or code that already ran. Tests use an inert marker-writing client and a real pseudo-terminal; a live Claude startup/session integration is still unverified. The launch command is deliberately not exposed over MCP.

## MCP setup

Copy [examples/mcp.json](examples/mcp.json) into your client's MCP configuration after replacing **all absolute paths**. The server stays restricted to the root selected at startup. A tool call cannot switch the root or turn networking on.

```json
{
  "mcpServers": {
    "protection-agency": {
      "command": "/absolute/path/to/python3",
      "args": ["-I", "/trusted/protection-agency/guard.py", "serve", "--root", "/path/to/project", "--online"]
    }
  }
}
```

Remove `--online` for offline use. Four tools are exposed:

| Tool | Purpose |
| --- | --- |
| `scan_project(level)` | Return a summary, up to five findings, and coverage gaps |
| `get_findings(report_id, offset?, finding_id?)` | Retrieve up to ten detailed findings per request |
| `check_command(command)` | Classify command text without executing it |
| `check_dependency(ecosystem, name, version?, registry?)` | Inspect a proposed release with explicit coverage limits |

The last eight reports remain in process memory. Restarting the server discards them. No scanner reports are written into the inspected repository. Static findings are cached by content hash, but files are reread on every scan. Online advisory queries are fresh on every scan; an unchanged lockfile does not suppress intelligence refresh. MCP results are evidence: they do not intercept the client's other tools.

## Claude Code hooks and the portable skill

[examples/claude-settings.json](examples/claude-settings.json) contains a configuration fragment for a trusted **user-level** Claude settings file. Replace the interpreter and scanner paths, merge it with existing hooks, and restart Claude. Do not put the policy's executable code in an untrusted target repository.

- `SessionStart` screens the project and adds a short context report. This event does not block actions.
- Startup findings identify execution surfaces; the SessionStart adapter cannot intercept other startup hooks or editor tasks that already run. The separate user-invoked `launch` gate inspects before starting a selected client, within its documented scope.
- `PreToolUse` screens Bash command text. Recognized high-priority patterns are denied. A very small set of simple read commands returns no decision, leaving normal permissions in control. Other commands trigger a standard project scan, then a deny or a request for user review. This includes installs, builds, tests, inline interpreters, and Git commands that could invoke helpers.
- Project advisory status and proposed-release advisory status are reported separately. A project with no matching dependencies does not establish coverage for a proposed installation.
- The example sets `onFailure: "block"` and a 90-second timeout. That failure behavior requires **Claude Code v2.1.295+**. Verify it on the client you actually use: temporarily point the hook at a missing file and confirm that a Bash call is blocked. Older clients may continue when hooks cannot start or time out.
- Only the Bash tool is integrated. Other execution tools, MCP servers that execute code, IDE autorun, another terminal, and users disabling the hook are outside this adapter's control. Keep sandboxing and native permissions enabled.

The [portable skill](skills/protection-agency/SKILL.md) guides agents through scan, review, and rescan. Install it in the trusted skill location supported by your client. Skills are instructions, so they are weaker than enforced hooks. This alpha supplies an example and does not modify your agent configuration automatically.

## Does it update itself?

**Live advisories: yes, when an online scan runs. Executable code and bundled rules: no.**

OSV maintains its advisory database independently. This tool requests current results each time, subject to upstream coverage and publication delay. The bundled PolinRider snapshot was reviewed on **2026-11-10** and does not refresh itself. Changing the scanner or its rules currently means reviewing and upgrading to a new repository revision/release. There is no background updater, hosted backend, telemetry, or automatic installation.

The next planned update layer is a **data-only, authenticated rule feed** with release provenance, schema validation, freshness/rollback checks, and last-known-good behavior. It is a design in [the roadmap](docs/ROADMAP.md), not implemented functionality. A security tool's update channel must not become a new arbitrary-code execution path.

## Development and contributing

```bash
python3 -I -m unittest discover -s tests -v
```

Tests use synthetic strings and temporary projects. They do not fetch or execute malware. CI runs the same suite. A controlled synthetic benchmark is in [docs/VALIDATION.md](docs/VALIDATION.md); it is not a real-world detection-rate claim.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [architecture](docs/ARCHITECTURE.md), and [the threat model](docs/THREAT-MODEL.md). Useful contributions include parser fixtures, narrowly scoped signatures with sources, bypass regression cases, and client-specific hook adapters. Do not submit working malware payloads, private credentials, or unlicensed threat feeds.

This tool does not automatically remove files, fix dependencies, rotate credentials, or remediate an already compromised machine. If malicious code has executed, scanning the project alone cannot establish that the machine is trustworthy.

## Attribution and license

Created by [DocBadTouch](https://github.com/DocBadTouch). MIT licensed; contributions welcome. Advisory data and research retain their original attribution. Bundled package-version facts are sourced in [intelligence.py](src/protection_agency/intelligence.py), with background in [Sonatype's original research](https://www.sonatype.com/blog/polinrider-loader-reappears-in-hijacked-npm-packages). OSV API details: [official documentation](https://google.github.io/osv.dev/post-v1-querybatch/). Integration contracts: [Claude hooks](https://code.claude.com/docs/en/hooks) and [MCP stdio](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
