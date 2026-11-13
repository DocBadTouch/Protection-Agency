# Protection Agency

**Checks before your coding agent runs things.** Your agent needs an agency.

Protection Agency screens projects for known malicious package releases, published vulnerabilities, and suspicious code. Its Claude Code integration checks Bash commands before execution and can deny recognized dangerous patterns or ask you to review a command.

Created by [DocBadTouch](https://github.com/DocBadTouch). Free, MIT licensed, runs locally, and makes no AI/model calls.

**Source alpha `0.2.0a4` · Linux/macOS · Python 3.11+ · Claude Code 2.1.295+ for hooks.** A real Claude session has not yet been validated end to end. This is screening, not a guarantee that your computer or project is safe. Keep Claude's sandbox and native permissions enabled.

## Try it without running a project

You need Git and Python 3.11 or newer (`python3 --version`). In a trusted terminal, download this repository into your home directory, outside projects you inspect:

```bash
git clone https://github.com/DocBadTouch/Protection-Agency.git "$HOME/.protection-agency"
alias agency='python3 -I "$HOME/.protection-agency/guard.py"'
agency demo
```

The alias is a shortcut for this bash/zsh terminal; no shell startup file is edited. The tool is currently distributed as source, with no package-manager installation required. Use the official repository and a revision you trust. [Other installation details](docs/GETTING-STARTED.md).

The demo sends example text to the trusted hook and shows:

```text
Command text: npm install cdeops@13.5.31
BLOCKED by the guard: this exact release is listed as malicious in the bundled indicators.
```

**That example command is never executed.** No package is installed or downloaded. The demo tests the hook's responses, not a running Claude client.

## Set it up for Claude Code

From the same terminal, move to the project you want to work on and run guided setup:

```bash
cd /path/to/your-project
agency setup
```

Setup explains what it will add, asks about online vulnerability checks, previews the user settings change, and asks before applying it. It preserves unrelated settings, keeps private original-byte backups, and tests the trusted hook's responses. It does not start Claude or approve the project. Restart Claude afterward and inspect `/hooks` to confirm the settings it actually loads.

Then, before working with Claude:

```bash
agency open --online
```

This checks the current project **before starting Claude**, then uses the existing launch gate to stop on high-priority findings or incomplete coverage. It finds an installed Claude executable outside the project on the sanitized PATH; it never downloads one. Findings can stop startup for review. During the session, installed hooks screen Bash commands. Expect review prompts for installs, builds, tests, and other execution in this alpha.

`--online` sends eligible public dependency names/versions to the OSV advisory service, not source code or credentials. Keep confidential inventories offline. The startup gate requires completed online coverage; offline checks remain useful but will not authorize a client launch. [Privacy and supported scope](docs/THREAT-MODEL.md).

For a project check without opening Claude:

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
agency uninstall-hooks --project . --human
```

For custom profiles, pass the same absolute `--settings` path used during setup. Removal preserves unrelated settings and later edits; private backups remain local.

## Does it update itself?

Online checks request current eligible vulnerability advisories when they run. The scanner and bundled malicious-release indicators do **not** update themselves. The small bundled PolinRider snapshot was reviewed on **2026-11-10**. [Upgrade instructions](docs/USAGE.md#does-it-update-itself) explain deliberate source upgrades and restarting integrations.

## Go deeper or contribute

The recommended first-time path is `demo` → `setup` → `open`. An MCP server and a [portable skill](skills/protection-agency/SKILL.md) are also available for supported agent workflows; MCP/skills alone do not intercept other tools.

- [Getting started](docs/GETTING-STARTED.md): walkthrough, readable results, setup status, troubleshooting.
- [Detailed usage](docs/USAGE.md) and [CLI reference](docs/CLI.md): scan levels, inventories, MCP, hooks, launch review, JSON automation, and every command.
- [Validation](docs/VALIDATION.md), [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT-MODEL.md), and [roadmap](docs/ROADMAP.md): measured evidence, limits, and planned work.
- [Contributing](CONTRIBUTING.md), [security reporting](SECURITY.md), [changelog](CHANGELOG.md), and [license](LICENSE).
