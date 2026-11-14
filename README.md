# Protection Agency

**Checks before your coding agent runs things.** Your agent needs an agency.

Protection Agency screens projects for known malicious package releases, published vulnerabilities, and suspicious code. Use its CLI or read-only MCP tools with compatible agents, or select a Codex/Claude adapter for shell-command checks and a guard before startup.

Created by [DocBadTouch](https://github.com/DocBadTouch). Free, MIT licensed, runs locally, and makes no AI/model calls.

**Source alpha `0.3.0a1` · Python 3.11+ · Linux/macOS and experimental native Windows on local NTFS.** Real Codex/Claude sessions remain unverified. This is screening, not a guarantee that your computer or project is safe. Keep native sandboxing and permissions enabled. See the [agent/platform coverage matrix](docs/AGENTS-AND-PLATFORMS.md).

## Try it without running a project

You need Git and Python 3.11 or newer. In a trusted terminal, download this repository into your home directory, outside projects you inspect. On Linux/macOS:

```bash
git clone https://github.com/DocBadTouch/Protection-Agency.git "$HOME/.protection-agency"
alias agency='python3 -I "$HOME/.protection-agency/guard.py"'
agency agents
agency demo --agent codex
```

The alias is for this bash/zsh terminal; no startup file is edited. In Windows PowerShell, use a function instead:

```powershell
git clone https://github.com/DocBadTouch/Protection-Agency.git "$HOME\.protection-agency"
function agency { python -I "$HOME\.protection-agency\guard.py" @args }
agency agents
agency demo --agent codex
```

The tool is currently distributed as source, with no package-manager installation required. Use the official repository and a revision you trust. [Installation details](docs/GETTING-STARTED.md).

The demo sends example text to the trusted hook and shows:

```text
Command text: npm install cdeops@13.5.31
BLOCKED by the guard: this exact release is listed as malicious in the bundled indicators.
```

**That example command is never executed.** No package is installed or downloaded. The demo tests the selected hook's responses, not a running agent.

## Set it up for your agent

From the same terminal, move to the project you want to work on and run guided setup:

```bash
cd /path/to/your-project
agency setup
```

Setup asks whether you use Codex or Claude, explains what it will add, asks about online vulnerability checks, previews the user settings change, and asks before applying it. It preserves unrelated settings, keeps private original-byte backups, and tests the selected adapter's responses. It does not start an agent or approve the project. Restart the client afterward and inspect `/hooks`, including Codex's required native hook trust review.

Then, select the client to check before starting it:

```bash
agency open --agent codex --online
# Or: agency open --agent claude --online
```

This checks the current project **before starting the selected client**, stopping on high-priority findings or incomplete coverage. It discovers an installed external executable on the sanitized PATH; it never downloads one. Native Windows launch requires an `.exe`, with batch shims refused. Findings can stop startup for review.

During a session, installed hooks screen the client's shell tool. Claude can request native review. **Codex's experimental strict adapter denies commands needing review**, because Codex does not support hook `ask`; ordinary builds/tests may be blocked. Codex can continue after hook startup/timeout errors. Keep this limitation in mind before installing strict hooks; read-only MCP and the guard before startup remain separately useful. [Adapter behavior and limits](docs/AGENTS-AND-PLATFORMS.md).

`--online` sends eligible public dependency names/versions to the OSV advisory service, not source code or credentials. Keep confidential inventories offline. The startup gate requires completed online coverage; offline checks remain useful but will not authorize a client launch. [Privacy and supported scope](docs/THREAT-MODEL.md).

For a project check without opening an agent:

```bash
agency check --online
agency check --online --full
```

These checks never run project code. Use them after dependency changes and before shipping. They support npm and Python inventories; [the detailed guide](docs/USAGE.md) lists formats and limits.

## Understand the result

| You see | What to do |
| --- | --- |
| **STOP** | Keep project execution paused. Read the specific finding, evidence, and next action. A suspicious pattern can also be legitimate code. |
| **REVIEW NEEDED** | Read the findings and missing checks. Offline/failed/unsupported checks cannot establish current coverage. |
| **No known matches** | No matches were found in the checked scope. Continue using sandboxing and normal permissions; unknown attacks can be missed. |

Output includes where a finding came from and what to do next. `--full` shows remaining findings. [Getting started and troubleshooting](docs/GETTING-STARTED.md) explains common stops, custom profiles, and how to check your setup.

To remove the installed hooks from the current project's terminal:

```bash
agency uninstall-hooks --agent codex --project . --human
```

Choose the agent you installed, and for custom profiles pass the same absolute `--settings` path. Removal preserves unrelated settings and later edits; private backups remain local.

## Does it update itself?

Online checks request current eligible vulnerability advisories when they run. The scanner and bundled malicious-release indicators do **not** update themselves. The small bundled PolinRider snapshot was reviewed on **2026-11-10**. [Upgrade instructions](docs/USAGE.md#does-it-update-itself) explain deliberate source upgrades and restarting integrations.

## Go deeper or contribute

The first-time path is `demo --agent …` → `setup` → `open --agent …`. Any compatible MCP client can use the shared server; a [portable skill](skills/protection-agency/SKILL.md) guides scan/review/rescan. MCP/skills alone do not intercept other tools. Agent-specific adapters and platform safeguards are separate layers.

- [Getting started](docs/GETTING-STARTED.md): walkthrough, readable results, setup status, troubleshooting.
- [Agent/platform coverage](docs/AGENTS-AND-PLATFORMS.md): Codex, Claude, other MCP clients, and native Windows.
- [Detailed usage](docs/USAGE.md) and [CLI reference](docs/CLI.md): scan levels, inventories, MCP, hooks, launch review, JSON automation, and every command.
- [Validation](docs/VALIDATION.md), [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT-MODEL.md), and [roadmap](docs/ROADMAP.md): measured evidence, limits, and planned work.
- [Contributing](CONTRIBUTING.md), [security reporting](SECURITY.md), [changelog](CHANGELOG.md), and [license](LICENSE).
