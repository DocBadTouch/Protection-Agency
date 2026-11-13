# Getting started

Protection Agency helps inspect a project before an agent installs packages or runs code. It checks selected files/dependency identities, and its Claude adapter checks Bash commands during a session. It cannot detect every attack, isolate a running client, or establish that a computer is uncompromised.

Source alpha `0.2.0a4` supports Linux/macOS, Python 3.11+, and a trusted external Claude client. Git obtains the source; Claude Code 2.1.295+ is required for the hook failure policy. A real Claude session has not been validated end to end. Local tests explicitly report native enforcement as unverified.

## 1. Get the tool and see a harmless demonstration

Keep the scanner outside projects you inspect. In a trusted terminal:

```bash
python3 --version
git clone https://github.com/DocBadTouch/Protection-Agency.git "$HOME/.protection-agency"
alias agency='python3 -I "$HOME/.protection-agency/guard.py"'
agency demo
```

The alias works in the current bash/zsh terminal. In another terminal, define it again, or use `python3 -I "$HOME/.protection-agency/guard.py"` in place of `agency`. If the checkout already exists, use it instead of cloning over it. No shell startup files are changed. For another trusted installation location, substitute its absolute launcher path. Use the official repository and a reviewed revision; package/tagged release distribution is not published yet.

The demo starts only the trusted hook against a disposable empty project. The install line is **input text**, never an executed command. It checks a known-malicious install denial, a simple-read response that leaves native permissions in control, and malformed-event failure. It makes no network requests and installs no packages. A passed demo does not prove Claude invokes or enforces the hook.

## 2. Set up Claude checks once

From that same terminal, change into your project folder:

```bash
cd /path/to/your-project
agency setup
```

The wizard shows the project and user settings file. It asks whether installed hooks should query OSV for current advisories, then previews the two hook groups and asks before writing. Online mode sends eligible public package names/ecosystems/versions, not source, paths, or credentials. Choose offline for confidential inventories; provenance classification has limits in the [privacy model](THREAT-MODEL.md#privacy-and-intelligence).

Setup preserves unrelated settings and keeps a private original-byte backup before editing. JSON comments/formatting normalize. It refuses unsafe paths/permissions, explicit hook disabling, and detected conflicts. If settings change while you answer, it stops rather than applying a preview to another snapshot. Backups may contain existing secrets; keep them private. Setup does not approve the project, start Claude, change native permissions, or configure MCP/skills.

After installation, it validates configuration and exercises the trusted hook. **Local tests passed** and **native enforcement verified** are distinct states. Native version/loading, event delivery, order, timeout policy, and sandboxing still need verification in the actual client. Restart Claude and inspect `/hooks`, including configuration origin and commands. Keep its sandbox and permissions enabled.

Preview without prompts or settings writes:

```bash
agency setup --dry-run --online
```

Interactive setup requires a terminal and rejects piped consent. For deliberate automation, use explicit `install-hooks` ([CLI reference](CLI.md)). Cancelling the confirmation leaves settings unchanged. A failed test after installation leaves the new settings for inspection, instead of silently restoring an earlier snapshot.

### Custom Claude profiles

Guided setup uses `$CLAUDE_CONFIG_DIR/settings.json` if set; otherwise `~/.claude/settings.json`. An explicit absolute `--settings` path takes precedence:

```bash
agency setup --settings /absolute/claude-profile/settings.json
```

Match this file to the profile the native client loads. CLI overrides and complete settings precedence are not discovered. Older explicit `install-hooks`/`uninstall-hooks` default to the home profile unless given `--settings`. Configuration/interpreter/scanner paths must stay outside the inspected project; project-contained global configuration environment paths are rejected.

## 3. Check before opening Claude

From the project folder:

```bash
agency open --online
```

`open` finds `claude` on PATH after removing relative/project entries and delegates to the existing launch gate. A project executable or symlink into the project is rejected. It checks selected project text, dependencies, and selected Git startup metadata. High-priority findings, gaps, failed/offline advisories, changed content, and expired checks stop startup. It provides no OS sandbox or immutable filesystem snapshot.

Select a trusted external client or preview startup with:

```bash
agency open --online --client /absolute/path/to/claude
agency open --online --dry-run
```

Arguments after `--` go to the client literally, without shell expansion. Client/global configuration and chosen client arguments remain trusted inputs. `open` does not install hooks; setup provides in-session checks separately.

When startup stops, read `agency check --online --full`. With complete coverage and at most 50 lower-priority findings, `agency open --online --review` can display all review metadata and require a one-time terminal challenge. High-priority findings and incomplete checks cannot be approved that way. Do not automate the challenge. Installed hooks deny recognized dangerous patterns and ask for review on other execution such as installs/builds/tests; other tools are not intercepted.

Offline mode can screen files and command text, but the startup gate requires completed online advisory coverage. Online choices during setup configure installed hooks; `check` and `open` each require their own explicit `--online` flag.

## Read findings and check your setup

```bash
agency check --online
agency check --online --full
agency doctor --root . --settings "$HOME/.claude/settings.json" --probe-hooks --human
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
| Hooks are disabled | Inspect user/project `disableAllHooks`; the tool never silently flips it. Project matches produce `PA408`. |
| Claude cannot be found | Supply `--client /absolute/path/to/claude` for your trusted external installation. No client is downloaded. |
| Startup has incomplete checks | Read gaps and the detailed guide. Unsupported inventory/config/Git layouts and private/unknown provenance remain gaps; review cannot override them. |
| Frequent review prompts | This alpha asks on many ordinary execution commands. Read findings, keep permissions enabled, and report benign cases with inert fixtures. |
| Doctor passes, but hooks are absent | Confirm the exact native profile, restart Claude, and inspect `/hooks`. Local probes cannot verify native loading/delivery. |

Remove hooks with `agency uninstall-hooks --project . --human`, adding the explicit `--settings` path for custom profiles. Removal preserves unrelated settings/later edits; private backups/coordination locks remain. See [upgrades](USAGE.md#does-it-update-itself) for deliberate source updates and integration restarts.

Continue with [Detailed usage](USAGE.md), the [CLI reference](CLI.md), and [threat model](THREAT-MODEL.md) for inventories, budgets, MCP/skills, and scope. [Validation](VALIDATION.md) records evidence and outstanding real-client work.
