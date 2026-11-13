# CLI reference

This reference describes source version `0.2.0a3`, Python 3.11+, on Linux/macOS. Run the trusted checkout outside the inspected project with an external Python interpreter in isolated mode:

```bash
python3 -I /trusted/protection-agency/guard.py --version
python3 -I /trusted/protection-agency/guard.py --help
python3 -I /trusted/protection-agency/guard.py install-hooks --help
```

Replace placeholder paths with actual absolute paths. The source checkout includes everything needed at runtime; package distribution is not published. [README setup](../README.md) explains installation, privacy, supported inventories, and the client integration. Each subcommand accepts `--help`. Invalid arguments normally exit `2`; an ordinary CLI check error exits `3` without asserting safety. JSON fields/statuses are alpha interfaces and may change.

## Commands

| Command | Arguments and options | Effect |
| --- | --- | --- |
| `scan` | `root`, `--level quick\|standard\|deep` (default `standard`), `--online`, `--full` | Inspect selected project files as data. Return a compact report, or full findings with `--full`. |
| `check-command` | One quoted `command` string | Classify text as `deny`, `ask`, or `no_objection`; never execute it. |
| `check-dependency` | `npm\|PyPI name [version]`, `--registry URL`, `--online` | Check a proposed release without installing, resolving, or downloading artifacts. Exact supported versions and explicit public provenance are needed for OSV. |
| `serve` | Required `--root root`, optional `--online` | Serve four read-only MCP tools over stdio, fixed to that root and online mode. |
| `hook` | Optional `--online`; one event on stdin | Handle Claude `SessionStart` or `PreToolUse` Bash JSON. Never execute the proposed command. |
| `doctor` | Optional `--root root`, `--settings file`, `--probe-hooks` | Run offline self-checks and optional configuration/protocol diagnostics. Configuration checks require both root and settings. |
| `install-hooks` | Required `--project root`; optional `--settings file`, `--online`, `--dry-run` | Add/replace only this tool's Claude user hooks after checking trusted paths and explicit hook-disable controls. |
| `uninstall-hooks` | Required `--project root`; optional `--settings file`, `--dry-run` | Remove owned/exact legacy handlers while preserving current unrelated settings and later user edits. |
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
| `scan`, `check-dependency` | `0`: `no_findings`; `1`: `block`; `2`: `review`; `3`: check error. Read coverage and gaps alongside the decision. Offline scans require review. |
| `check-command` | `0`: `no_objection`; `1`: `deny`; `2`: `ask`. These are advisory text classifications. |
| `doctor` | `0`: all requested checks passed; `1`: a requested check failed; `3`: ordinary check/root error. Missing required argument combinations exit `2`. Native enforcement remains unverified. |
| Hook setup/removal | `0`: completed/no-op/preview; `2`: disabled controls, detected conflict, or an applied durability warning; `3`: ordinary setup error. Inspect `status` and `changed`. |
| `hook` | `0`: valid protocol output, including deny/ask responses; `2`: hook check failure. A denial is encoded in JSON rather than exit `1`. Client behavior on hook startup/timeout errors needs native verification. |
| `serve` | Newline-delimited JSON-RPC on stdout; clean input EOF exits `0`; an oversized transport frame exits `1`. Protocol errors use JSON-RPC error responses. Do not send console prose into its transport. |
| `launch` before child start | `1`: high-priority finding; `2`: review/incomplete/changed/expired state; `3`: check/start error; `130`: interruption. A dry run starts nothing. |
| `launch` after child start | Return the child exit status; preflight output's `execution` field distinguishes it from a guard refusal. |

## Hook setup and removal

Both setup commands default to `~/.claude/settings.json`. A custom `--settings` path must be absolute and outside the selected project, matching the user profile the native client loads. `CLAUDE_CONFIG_DIR`, CLI overrides, and the complete native hierarchy are not discovered automatically. The explicit `--project` selects the untrusted root for trust-boundary and root hook-disable checks; setup does not approve or fully scan it.

An edit normalizes JSON comments/formatting, preserves unrelated settings semantically, and writes a private original-byte backup before replacement. It refuses unsafe ownership/write permissions, symlinks, hard-linked settings, invalid/oversized JSON, and detected conflicting edits. The reserved `statusMessage: "Protection Agency security check"` identifies owned handlers and is not authentication. Removal also recognizes exact legacy handlers for the current trusted paths. It does not blindly restore an earlier backup. Backups and the empty coordination lock remain local; backups may contain credentials. Review [the full setup behavior](../README.md#claude-code-hooks-and-the-portable-skill) and [editing limits](THREAT-MODEL.md#explicit-user-hook-setup-boundary).

| Setup `status` | Meaning and next action |
| --- | --- |
| `installed`, `uninstalled` | Requested edit applied; `changed: true`. Restart the client after changes and inspect its native hook list. |
| `already_installed`, `not_installed` | No edit needed; `changed: false`. |
| `would_install`, `would_uninstall` | Dry-run preview only; no files/directories created. `changed: false` describes actual writes, not the predicted edit. |
| `disabled`, `disabled_by_project` | Explicit user/root-project hook disabling prevents installation. Inspect the control; setup never silently overrides it. |
| `conflict` | A detected content/directory change or active setup lock prevented replacement. Inspect current settings and retry deliberately. A private backup may already exist. |
| `applied_with_warning` | Replacement happened, but directory durability sync failed. `changed: true`; inspect the resulting settings instead of assuming rollback. |

The lock coordinates this tool's writers. Another editor can ignore it and race the final check/rename, so avoid concurrent settings edits. Existing `disableAllHooks` does not prevent surgical uninstall of this tool's handlers. After a source/interpreter move, use the current trusted installation to preview/reinstall marked hooks, update MCP paths, and rerun diagnostics. Old unmarked legacy paths require manual review.

## Doctor

```bash
python3 -I /trusted/protection-agency/guard.py doctor --root /path/to/project
python3 -I /trusted/protection-agency/guard.py doctor --root /path/to/project --settings /absolute/user/settings.json
python3 -I /trusted/protection-agency/guard.py doctor --root /path/to/project --settings /absolute/user/settings.json --probe-hooks
```

The first command runs six scanner self-checks. The second adds canonical hook configuration validation and selected root project hook-disable checks. The third additionally reconstructs the trusted guard arguments and checks three inert PreToolUse events: known-malicious installation text must deny, a simple read must return no decision, and malformed input must exit `2`. No proposed command, package manager, unrelated configured hook, or native client runs. The probe makes no advisory requests, even for online hook profiles.

| Integration `status` | Meaning |
| --- | --- |
| `configured` | The two marked groups match the current canonical profile and selected disable controls did not invalidate it. This does not mean the native client loaded them. |
| `missing` | Settings or marked hooks were absent. |
| `manual_configuration` | Exact unmarked legacy handlers were found. Review/adopt them through an authorized setup task. |
| `disabled`, `disabled_by_project` | User or selected root project configuration explicitly disables hooks. |
| `modified` | Marked hook count, event, group, command/arguments, matcher, timeout, online mode, or failure policy differs. Arbitrary settings commands are never probed. |
| `unsafe_or_invalid` | Trusted-path/permission, file-read, settings-parse, or project-control checks failed. No configured result is asserted. |
| `changed_during_check` | Settings changed during the probe; its result is not verified. |
| `check_failed` | A configured profile's probe encountered an error, such as timeout or malformed output. |

Probe values are `not_run`, `requires_isolated_python`, `passed`, `failed`, or `not_verified`. `passed` verifies this tool's responses only. The top-level `self_checks_passed` means the requested local checks passed, while `failed` means at least one failed. Doctor keeps `live_client_enforcement: not_verified`; integration results report the actual native version as `not_checked`. The configured failure policy requires **Claude Code v2.1.295+**. Inspect `/hooks` in the actual client and independently test delivery, startup/timeout failure behavior, settings precedence, and sandboxing with inert fixtures before relying on enforcement. No live Claude integration has been validated by this repository yet.

Keep the [portable skill](../skills/protection-agency/SKILL.md) aligned with these limits. Official contracts: [Claude hooks](https://code.claude.com/docs/en/hooks), [settings hierarchy](https://code.claude.com/docs/en/settings), and [MCP stdio](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports). [Validation](VALIDATION.md) records automated evidence; [the roadmap](ROADMAP.md) separates planned native-client tests and authenticated updates from current functionality.
