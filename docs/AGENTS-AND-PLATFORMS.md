# Agents and platforms

Protection Agency's scanner, dependency checks, command policy, and MCP tools are shared. Agent adapters translate hook configuration/events; filesystem backends supply platform-specific safeguards. Source `0.3.0a1` adds Codex and native Windows implementation and tests. Native vendor-client enforcement remains unverified for both adapters.

## Choose an agent

```bash
agency agents
agency setup --agent codex
agency open --agent codex --online
```

Interactive `setup` asks which agent you use if `--agent` is omitted. A noninteractive preview needs an explicit agent. `open` needs an agent for automatic discovery or an explicit trusted `--client` executable. No user preference file is silently created. Existing `hook`, `doctor`, and explicit hook-edit commands retain a Claude default for compatibility; select `--agent codex` for Codex profiles/protocols.

| Layer | Codex | Claude Code | Other agents |
| --- | --- | --- | --- |
| CLI checks | Shared | Shared | Shared |
| Read-only MCP | Configuration example provided | Configuration example provided | Compatible stdio clients can configure the same four tools |
| Before-start gate | Select `--agent codex` | Select `--agent claude` | Explicit external `--client`/`launch` |
| Session context | Implemented adapter | Implemented adapter | Adapter needed |
| Shell command hook | Experimental strict denials | Denials and native review requests | Adapter needed |
| Actual native enforcement | **Unverified** | **Unverified** | **Unverified** |

MCP tools act when called. Skills are instructions. Neither gives the server control over a client's other tools. The gate only protects launches routed through it. GUI/IDE sessions, other execution tools, global/client configuration, and commands started elsewhere need their own controls and sandboxing.

## Codex adapter contract

The contract reference is Codex `0.169.0`; actual installed versions are not queried. Configuration goes to `$CODEX_HOME/hooks.json` or `~/.codex/hooks.json`, with explicit `--settings` taking precedence. Native hook trust must be reviewed in `/hooks`; setup never bypasses trust or changes native permissions. The shared skill and [MCP example](../examples/codex-mcp.toml) are optional.

Codex does not implement hook `ask`. This adapter converts review-needed commands to explicit denials, so ordinary builds/tests may be blocked. It never sends unsupported `ask` or rewrites a call into an approval. Adapter parsing/check errors emit JSON denials; missing executables and native timeouts can still allow execution. Do not treat installation/probe success as a fail-closed native boundary. The [official hook contract](https://developers.openai.com/codex/hooks) documents these limitations.

Handlers use fixed trusted interpreter/source paths. POSIX commands are shell-quoted; Windows uses a system PowerShell relay carrying encoded literal argv, with no target data embedded. This accommodates cmd/PowerShell quoting without loading profiles. Only the trusted guard runs. Reference implementation: [Codex command runner at 0.169.0](https://github.com/openai/codex/blob/rust-v0.169.0/codex-rs/hooks/src/engine/command_runner.rs) and [PreToolUse parser](https://github.com/openai/codex/blob/rust-v0.169.0/codex-rs/hooks/src/events/pre_tool_use.rs).

Project `.codex/config.toml` hook-disable controls produce high-priority `PA409`. Setup/doctor also read the selected user profile's sibling `config.toml`, refusing explicit disabled hooks or managed-only hooks. TOML is read as data and never modified. Full native precedence, managed requirements, plugins, tool coverage, and hook trust remain subject to native-client verification.

## Platform scope

| Platform | Filesystem/backend | Terminal shortcut | Client launch |
| --- | --- | --- | --- |
| Linux/macOS | Existing no-follow directory descriptors, bounded reads, owner/mode checks, advisory locks | bash/zsh alias | Explicit trusted external executable or selected agent discovery |
| Native Windows | Experimental local fixed NTFS backend, native handles, reparse refusal, conservative owner/DACL checks, native locks | PowerShell function | Native `.exe` only; `.cmd`/`.bat` shims refused |
| WSL | Separate Linux environment | Linux instructions | Does not establish coverage of native Windows applications |

Windows uses handle-relative file operations and handle-based bounded enumeration. Read directory pins deny concurrent write/delete opens; the protected settings parent permits write sharing needed by native rename while retaining its identity through the handle. Junctions, symlinks, other reparse points, alternate data streams, reserved names, UNC/network/removable drives, relative-drive paths, and unsupported filesystems are refused. Settings must have a current-user or trusted SYSTEM/Administrators owner; foreign write grants/unsupported ACL entries and hard-linked settings are rejected. OWNER RIGHTS entries refer to that validated owner. New settings/backups have protected ACLs restricted to the current user, SYSTEM, and Administrators. Those privileged Windows principals remain trusted. Directory durability after rename is explicitly not attested.

Reads, private backups, locks, handle-relative replacement, ACL rejection, junction refusal, shell-relay quoting, and native process markers have dedicated Windows tests. POSIX mode/terminal tests are identified separately; a skipped POSIX test is not Windows evidence. See [validation](VALIDATION.md) and the [CI workflow](../.github/workflows/tests.yml). Windows CI does not verify every retail Windows version or a real Codex/Claude session.

## Native Windows quick start

In PowerShell with Python 3.11+ and Git installed:

```powershell
git clone https://github.com/DocBadTouch/Protection-Agency.git "$HOME\.protection-agency"
function agency { python -I "$HOME\.protection-agency\guard.py" @args }
agency demo --agent codex
Set-Location C:\path\to\your-project
agency setup --agent codex
agency open --agent codex --online
```

The function exists only in the current terminal. `python` must select a supported trusted interpreter; use its absolute path if necessary. Automatic discovery looks for the selected native `.exe` on the sanitized external PATH, without current-directory lookup. Supply `--client C:\absolute\path\to\codex.exe` when needed. This tool never downloads clients. Use a local NTFS project and keep scanner/settings/interpreter paths outside it.

To inspect/remove a Codex custom profile, give the same settings path:

```powershell
agency doctor --agent codex --root . --settings "$HOME\.codex\hooks.json" --probe-hooks --human
agency uninstall-hooks --agent codex --project . --settings "$HOME\.codex\hooks.json" --human
```

Online checks remain explicit and provenance-limited. The launcher supplies no sandbox; use native isolation and minimal credentials. Unknown attacks and unsupported scopes may be missed.
