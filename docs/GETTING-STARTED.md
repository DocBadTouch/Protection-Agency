# Getting started

Protection Agency helps inspect a project before an agent installs packages or runs code. Its shared scanner/MCP tools inspect selected files and dependency identities. Codex and Claude adapters add shell-command checks; other compatible MCP clients can use advisory tools. It cannot detect every attack, isolate a running client, or establish that a computer is uncompromised.

Source alpha `0.3.0a1` requires Python 3.11+ and supports Linux/macOS plus experimental native Windows on local NTFS. You supply a trusted external client. The reviewed contract references are Claude Code 2.1.295 and Codex 0.169.0; actual installed versions and native enforcement remain unverified. See [agent/platform coverage](AGENTS-AND-PLATFORMS.md) for important differences, Windows instructions, and supported filesystem limits.

## 1. Get the tool and see a harmless demonstration

Keep the scanner outside projects you inspect. In a trusted terminal:

```bash
python3 --version
git clone https://github.com/DocBadTouch/Protection-Agency.git "$HOME/.protection-agency"
alias agency='python3 -I "$HOME/.protection-agency/guard.py"'
agency agents
agency demo --agent codex
```

The alias works in this bash/zsh terminal. [Windows PowerShell uses a function](AGENTS-AND-PLATFORMS.md#native-windows-quick-start). In another terminal, define the shortcut again, or use the trusted absolute Python/launcher paths directly. If the checkout already exists, use it instead of cloning over it. No startup files are changed. Use the official repository and a reviewed revision; package/tagged release distribution is not published yet.

The demo starts only the trusted hook against a disposable empty project. The install line is **input text**, never an executed command. It checks a known-malicious install denial, a simple-read response that leaves native permissions in control, and malformed-event failure. It makes no network requests and installs no packages. A passed demo does not prove the native client invokes or enforces the hook.

## 2. Choose your agent and set up checks

From that same terminal, change into your project folder:

```bash
cd /path/to/your-project
agency setup
```

The wizard asks which agent you use, then shows the project/user profile. You can select directly with `setup --agent codex` or `setup --agent claude`. It asks about online advisories, previews the two groups, and requires terminal confirmation before writing. Online mode sends eligible public dependency identities, not source, paths, or credentials. Keep confidential inventories offline; see the [privacy model](THREAT-MODEL.md#privacy-and-intelligence).

Setup preserves unrelated settings and keeps a private original-byte backup before editing. JSON comments/formatting normalize. It refuses unsafe paths/permissions, explicit hook disabling, and detected conflicts. If settings change while you answer, it stops rather than applying a preview to another snapshot. Backups may contain existing secrets; keep them private. Setup does not approve the project, start an agent, change native permissions, or configure MCP/skills.

After installation, it validates configuration and exercises the selected trusted adapter. **Local tests passed** and **native enforcement verified** are distinct states. Restart the client and inspect `/hooks`; Codex requires explicit native trust review. Its strict adapter denies review-needed commands because hook `ask` is unavailable, and native hook failures/timeouts can still continue. Keep native sandboxing and permissions enabled. Actual native loading, delivery, failure behavior, and sandbox integration still need real-client validation.

Preview without prompts or settings writes:

```bash
agency setup --agent codex --dry-run --online
```

Interactive setup requires a terminal and rejects piped consent. For deliberate automation, use explicit `install-hooks` ([CLI reference](CLI.md)). Cancelling the confirmation leaves settings unchanged. A failed test after installation leaves the new settings for inspection, instead of silently restoring an earlier snapshot.

### Custom agent profiles

Codex uses `$CODEX_HOME/hooks.json` or `~/.codex/hooks.json`. Claude uses `$CLAUDE_CONFIG_DIR/settings.json` or `~/.claude/settings.json`. An absolute `--settings` path takes precedence:

```bash
agency setup --agent codex --settings /absolute/codex-profile/hooks.json
```

Match the file to the native profile. Full precedence and client CLI overrides are not discovered. Explicit hook commands retain a Claude default for compatibility; pass `--agent codex` for Codex. They use the selected agent's known environment directory or home profile unless `--settings` is given. All trusted paths stay outside the inspected project.

## 3. Check before opening your agent

From the project folder:

```bash
agency open --agent codex --online
```

`open` discovers the selected agent outside the project on the sanitized PATH and delegates to the existing launch gate. Project executables and symlinks into the project are rejected. On native Windows it searches `.exe` files without current-directory lookup and refuses batch shims. It checks selected project text, dependencies, and Git startup metadata, stopping on high findings, incomplete/failed/offline checks, changes, and expiration. It provides no OS sandbox or immutable snapshot.

Select a trusted external client or preview startup with:

```bash
agency open --agent codex --online --client /absolute/path/to/codex
agency open --agent claude --online --dry-run
```

Arguments after `--` go to the client literally, without shell expansion. Client/global configuration and chosen client arguments remain trusted inputs. `open` does not install hooks; setup provides in-session checks separately.

When startup stops, read `agency check --online --full`. With complete coverage and at most 50 lower-priority findings, `agency open --agent codex --online --review` can display review metadata and require a one-time terminal challenge. High findings and incomplete checks cannot be approved that way. Do not automate it. In-session behavior differs: Claude requests native review for ordinary execution, while Codex's strict adapter denies it. Other execution tools are outside these shell adapters.

Offline mode can screen files and command text, but the startup gate requires completed online advisory coverage. Online choices during setup configure installed hooks; `check` and `open` each require their own explicit `--online` flag.

## Read findings and check your setup

```bash
agency check --online
agency check --online --full
agency doctor --agent codex --root . --settings "$HOME/.codex/hooks.json" --probe-hooks --human
```

For custom profiles, give doctor the path you installed. `check` shows a decision, selected file/dependency counts, advisory coverage, findings with locations/actions/references, and missing checks. It never executes project commands. Default output shows up to five findings/gaps; `--full` expands them. Use `check --json` or the existing JSON `scan` command for scripts.

- **STOP:** keep execution paused; inspect exact evidence/actions. Published malicious versions and heuristics are different evidence; legitimate code can match heuristics.
- **REVIEW NEEDED:** findings or missing checks need attention. Zero local findings with offline advisories still requires review.
- **No known matches:** no matches in the requested scope; unknown attacks and unsupported content may be missed. Keep normal permissions/sandboxing.

Doctor reports local checks, configuration, and trusted response tests separately. A pass does not mean the native client loaded the file. [Diagnostic statuses](CLI.md#doctor) explain failures. No result certifies host integrity or safe deployment to end users.

## Common stops

| What happens | Next step |
| --- | --- |
| Python is missing/older than 3.11 | Select a supported interpreter from a trusted source; check `python3 --version`. This tool does not install Python. |
| Scanner is inside the project | Keep it in its separate home directory; run setup from the actual project or pass its path. |
| Setup needs a terminal | Run in your own terminal; `--dry-run` previews without consent/edits. Explicit setup commands support deliberate automation. |
| Settings are unsafe, invalid, or changed | Inspect path, ownership/permissions, JSON, and current edits. Do not loosen permissions to force installation. |
| Hooks are disabled | Inspect Claude `disableAllHooks` (`PA408`) or Codex hook-disable/managed-only controls (`PA409`). The tool never silently flips them. |
| Agent cannot be found | Select `--agent codex`/`--agent claude`, or supply an absolute trusted executable. Windows needs a native `.exe`. No client is downloaded. |
| Startup has incomplete checks | Read gaps and the detailed guide. Unsupported inventory/config/Git layouts and private/unknown provenance remain gaps; review cannot override them. |
| Frequent prompts or denials | Claude asks on many ordinary execution commands; strict Codex hooks deny review-needed cases. Read findings, keep permissions enabled, and report benign cases with inert fixtures. |
| Doctor passes, but hooks are absent | Confirm the exact native profile, restart the client, and inspect/trust `/hooks`. Local probes cannot verify native loading/delivery. |
| Native Windows rejects a path or ACL | Use local fixed NTFS and direct paths. Inspect access controls and reparse points; network shares, alternate streams, and foreign write grants are refused. |

Remove hooks with `agency uninstall-hooks --agent codex --project . --human` (choose the installed agent), adding `--settings` for custom profiles. Removal preserves unrelated settings/later edits; backups/locks remain. See [upgrades](USAGE.md#does-it-update-itself) for deliberate updates and restarts.

Continue with [Detailed usage](USAGE.md), the [CLI reference](CLI.md), and [threat model](THREAT-MODEL.md) for inventories, budgets, MCP/skills, and scope. [Validation](VALIDATION.md) records evidence and outstanding real-client work.
