# CLI reference

This reference describes source `0.3.0a1`, Python 3.11+, Linux/macOS and experimental native Windows on local NTFS. Follow [Getting started](GETTING-STARTED.md) and [agent/platform coverage](AGENTS-AND-PLATFORMS.md). The `agency` shortcut is a terminal alias/function, not a separately installed binary. Keep the trusted checkout/interpreter outside inspected projects and use isolated Python:

```bash
python3 -I /trusted/protection-agency/guard.py --version
python3 -I /trusted/protection-agency/guard.py --help
python3 -I /trusted/protection-agency/guard.py install-hooks --help
```

Replace placeholder paths with actual absolute paths. The source checkout includes everything needed at runtime; package distribution is not published. [README setup](../README.md) explains installation, privacy, supported inventories, and the client integration. Each subcommand accepts `--help`. Invalid arguments normally exit `2`; an ordinary CLI check error exits `3` without asserting safety. JSON fields/statuses are alpha interfaces and may change.

## Commands

| Command | Arguments and options | Effect |
| --- | --- | --- |
| `agents` | Optional `--json` | Report adapter capabilities and platform backend separately from unverified native enforcement. |
| `demo` | Optional `--agent codex\|claude` (legacy default Claude), `--json` | Exercise the selected trusted adapter in a disposable empty project. No example commands or network requests. |
| `setup` | Optional `[root]`, `--agent codex\|claude`, `--settings file`, `--online` or `--offline`, `--dry-run` | Guided selected-agent hook setup. Interactive setup asks for the agent if omitted; noninteractive preview requires it. Show privacy/strict-policy limits, preview, confirm, then validate locally. |
| `check` | Optional `[root]` (default current directory), `--level quick\|standard\|deep`, `--online`, `--full`, `--json` | Same scanner and exit decisions as `scan`, with readable findings/actions by default. `--json` provides the existing summary/full report shape. |
| `open` | Optional `[root]`, `--agent codex\|claude`, `--client /absolute/executable`, `--online`, `--review`, `--dry-run`, optional `-- [client args…]` | Discover the selected external agent, or use an explicit trusted client. Without agent/client selection it stops. Same launch gate, readable receipts, literal args. Windows needs `.exe`. |
| `scan` | `root`, `--level quick\|standard\|deep` (default `standard`), `--online`, `--full` | Inspect selected project files as data. Return a compact report, or full findings with `--full`. |
| `check-command` | One quoted `command` string | Classify text as `deny`, `ask`, or `no_objection`; never execute it. |
| `check-dependency` | `npm\|PyPI name [version]`, `--registry URL`, `--online` | Check a proposed release without installing, resolving, or downloading artifacts. Exact supported versions and explicit public provenance are needed for OSV. |
| `serve` | Required `--root root`, optional `--online` | Serve four read-only MCP tools over stdio, fixed to that root and online mode. |
| `hook` | Optional `--agent codex\|claude`, `--online`; one event on stdin | Selected `SessionStart`/`PreToolUse` shell adapter. Legacy default Claude. Never execute proposed commands. |
| `doctor` | Optional `--agent codex\|claude`, `--root root`, `--settings file`, `--probe-hooks`, `--human` | Offline checks plus selected configuration/protocol diagnostics; both root/settings required for configuration checks. JSON default, readable summary optional. Legacy agent default Claude. |
| `install-hooks` | Required `--project root`; optional `--agent codex\|claude`, `--settings file`, `--online`, `--dry-run`, `--human` | Explicit agent hook edit. Legacy agent default Claude; select Codex explicitly. Preserve unrelated settings and refuse disable controls. |
| `uninstall-hooks` | Required `--project root`; optional `--agent codex\|claude`, `--settings file`, `--dry-run`, `--human` | Remove selected-agent owned handlers while preserving unrelated settings/later edits. Legacy default Claude. |
| `launch` | `root`, `--online`, `--review`, `--dry-run`, then required `-- /absolute/client [args…]` | Inspect before starting an explicitly selected trusted external client. This command can execute that client; it does not sandbox it. |

Offline is the default. `--online` opts into OSV requests for eligible public package names/ecosystems/versions; source, credentials, and project paths are not sent. Online mode does not download package artifacts. `launch` requires completed current advisory coverage to proceed, so an offline launch stops before execution. No command installs hook settings as a side effect of scanning, serving MCP, or running doctor.

```bash
python3 -I /trusted/protection-agency/guard.py check-command 'npm install example@1.0.0'
python3 -I /trusted/protection-agency/guard.py check-dependency npm example 1.0.0 --registry https://registry.npmjs.org --online
```

These examples inspect text/metadata only. A proposed-release result excludes transitive packages and package bytes. `no_objection` and `no_findings` do not authorize execution or guarantee safety.

## Results and exits

| Operation | Exit/status meaning |
| --- | --- |
| `demo` | `0`: all three trusted responses passed; `1`: demonstration failed; `3`: ordinary CLI error. Native enforcement remains unverified. |
| `setup` | `0`: preview completed or local configuration/response checks passed; `2`: cancellation, nonterminal input, disabled/conflicting settings, applied durability warning, or unsuccessful post-install validation; `3`: ordinary setup/self-check error; `130`: interruption. A failed post-install probe does not roll back an applied edit. |
| `scan`, `check`, `check-dependency` | `0`: `no_findings`; `1`: `block`; `2`: `review`; `3`: check error. Read coverage and gaps alongside the decision. Offline scans require review. |
| `check-command` | `0`: `no_objection`; `1`: `deny`; `2`: `ask`. These are advisory text classifications. |
| `doctor` | `0`: all requested checks passed; `1`: a requested check failed; `3`: ordinary check/root error. Missing required argument combinations exit `2`. Native enforcement remains unverified. |
| Hook setup/removal | `0`: completed/no-op/preview; `2`: disabled controls, detected conflict, or an applied durability warning; `3`: ordinary setup error. Inspect `status` and `changed`. |
| `hook` | `0`: valid protocol output, including denials. Claude review uses `ask`, failures exit `2`. Codex maps review/check errors to JSON denials with exit `0` because native `ask` is unsupported. Native startup/timeout failure can still continue. |
| `serve` | Newline-delimited JSON-RPC on stdout; clean input EOF exits `0`; an oversized transport frame exits `1`. Protocol errors use JSON-RPC error responses. Do not send console prose into its transport. |
| `launch`, `open` before child start | `1`: high-priority finding; `2`: review/incomplete/changed/expired state; `3`: check/start/client-discovery error; `130`: interruption. A dry run starts nothing. |
| `launch`, `open` after child start | Return the child exit status. `launch` JSON's `execution` field, or `open`'s readable starting message, distinguishes phases. |

Setup uses the selected agent's known environment directory (`CODEX_HOME`/`CLAUDE_CONFIG_DIR`) or home profile, unless `--settings` overrides it. Codex uses `hooks.json`; Claude uses `settings.json`. Python `-I` and terminal confirmation are required for wizard writes, with explicit online choice and snapshot-bound consent. `--dry-run` needs an agent, defaults offline without a mode flag, and creates no configuration/self-test files. No persistent alias/profile edit, client start, or project approval occurs. Terminal hints use platform-appropriate quoting.

`open` removes unsafe PATH entries before selected-agent discovery; the gate rejects executables resolved inside the project. Windows searches `.exe` only without current-directory lookup, and refuses batch clients. Complete coverage/high-priority/recheck/challenge rules remain unchanged. `open --online` and setup's online choice are separate; setup configures hooks only. Existing JSON/MCP contracts remain available. `agents` reports the Codex/Claude capability differences.

## Hook setup and removal

Explicit setup commands retain a Claude default; `--agent codex` selects Codex. Defaults honor the selected agent's environment/home directory. A custom settings path must be absolute, outside the project, and match the native profile. Full precedence/CLI overrides are not discovered. `--project` establishes the trust boundary and selected root hook-disable controls; installation does not approve or fully scan it. POSIX owner/mode and native Windows owner/DACL checks are separate safeguards.

An edit normalizes JSON comments/formatting, preserves unrelated settings semantically, and writes a private original-byte backup before replacement. It refuses unsafe ownership/write permissions, symlinks, hard-linked settings, invalid/oversized JSON, and detected conflicting edits. The reserved `statusMessage: "Protection Agency security check"` identifies owned handlers and is not authentication. Removal also recognizes exact legacy handlers for the current trusted paths. It does not blindly restore an earlier backup. Backups and the empty coordination lock remain local; backups may contain credentials. Review [the full setup behavior](USAGE.md#claude-code-hooks-and-the-portable-skill) and [editing limits](THREAT-MODEL.md#explicit-user-hook-setup-boundary).

| Setup `status` | Meaning and next action |
| --- | --- |
| `installed`, `uninstalled` | Requested edit applied; `changed: true`. Restart the client after changes and inspect its native hook list. |
| `already_installed`, `not_installed` | No edit needed; `changed: false`. |
| `would_install`, `would_uninstall` | Dry-run preview only; no files/directories created. `changed: false` describes actual writes, not the predicted edit. |
| `disabled`, `disabled_by_project`, `disabled_by_agent_settings` | Explicit selected user/project controls prevent installation. Codex uses `disabled_by_agent_settings` for hook-disable/managed-only controls. Setup never silently overrides them. |
| `conflict` | A detected content/directory change or active setup lock prevented replacement. Inspect current settings and retry deliberately. A private backup may already exist. |
| `applied_with_warning` | Replacement happened, but the final durability sync failed. `changed: true`; inspect the resulting settings instead of assuming rollback. Windows directory durability is separately unattested. |

The lock coordinates this tool's writers. Another editor can ignore it and race the final check/rename, so avoid concurrent settings edits. Existing `disableAllHooks` does not prevent surgical uninstall of this tool's handlers. After a source/interpreter move, use the current trusted installation to preview/reinstall marked hooks, update MCP paths, and rerun diagnostics. Old unmarked legacy paths require manual review.

## Doctor

```bash
python3 -I /trusted/protection-agency/guard.py doctor --root /path/to/project
python3 -I /trusted/protection-agency/guard.py doctor --root /path/to/project --settings /absolute/user/settings.json
python3 -I /trusted/protection-agency/guard.py doctor --root /path/to/project --settings /absolute/user/settings.json --probe-hooks
```

The first command runs six self-checks. Configuration checks validate selected-agent groups and root/user hook-disable controls. The probe reconstructs trusted argv and checks inert deny/read/error events. Claude malformed input exits `2`; Codex malformed input returns an explicit denial with exit `0`. No proposed command, package manager, unrelated hook, or native client runs, and no advisory requests occur. Select `--agent codex` for a Codex settings file.

| Integration `status` | Meaning |
| --- | --- |
| `configured` | The two marked groups match the current canonical profile and selected disable controls did not invalidate it. This does not mean the native client loaded them. |
| `missing` | Settings or marked hooks were absent. |
| `manual_configuration` | Exact unmarked legacy handlers were found. Review/adopt them through an authorized setup task. |
| `disabled`, `disabled_by_project`, `disabled_by_agent_settings` | Selected user/project configuration disables or suppresses user hooks. |
| `modified` | Marked hook count, event, group, command/arguments, matcher, timeout, online mode, or failure policy differs. Arbitrary settings commands are never probed. |
| `unsafe_or_invalid` | Trusted-path/permission, file-read, settings-parse, or project-control checks failed. No configured result is asserted. |
| `changed_during_check` | Settings changed during the probe; its result is not verified. |
| `check_failed` | A configured profile's probe encountered an error, such as timeout or malformed output. |

Probe values are `not_run`, `requires_isolated_python`, `passed`, `failed`, or `not_verified`. A pass verifies local responses only. Doctor retains `live_client_enforcement: not_verified` and native version `not_checked`; results also report `native_review_supported` and `hook_error_behavior`. Claude's failure policy needs 2.1.295+; Codex's reference contract is 0.169.0 with native error/timeout continuation and no hook `ask`. Inspect/trust `/hooks` and independently test delivery, effective settings, failures, and sandboxing. No real vendor-client enforcement has been validated yet.

Keep the [portable skill](../skills/protection-agency/SKILL.md) aligned with these limits. Official contracts: [Claude hooks](https://code.claude.com/docs/en/hooks), [settings hierarchy](https://code.claude.com/docs/en/settings), and [MCP stdio](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports). [Validation](VALIDATION.md) records automated evidence; [the roadmap](ROADMAP.md) separates planned native-client tests and authenticated updates from current functionality.
