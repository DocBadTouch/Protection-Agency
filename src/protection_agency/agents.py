"""Declared adapter contracts. Capabilities are separate from native verification."""
from dataclasses import dataclass, asdict
import base64
import os
from pathlib import Path
import re
import shlex


@dataclass(frozen=True)
class Agent:
    name: str
    label: str
    directory: str
    filename: str
    version_reference: str
    native_review_supported: bool
    hook_error_behavior: str


AGENTS = {
    "claude": Agent("claude", "Claude Code", ".claude", "settings.json", "2.1.295", True, "block_requires_supported_client"),
    "codex": Agent("codex", "Codex", ".codex", "hooks.json", "0.169.0", False, "may_continue_on_error_or_timeout"),
}


def get_agent(name):
    if name not in AGENTS:
        raise ValueError("unsupported agent; choose codex or claude")
    return AGENTS[name]


def default_settings(name, explicit=None):
    agent = get_agent(name)
    if explicit is not None:
        return Path(explicit).expanduser()
    override = os.environ.get("CODEX_HOME" if name == "codex" else "CLAUDE_CONFIG_DIR")
    return (Path(override) if override else Path.home() / agent.directory) / agent.filename


def capabilities():
    return {"platform": os.name, "scan_and_mcp": "local_ntfs" if os.name == "nt" else "posix",
            "agents": [{**asdict(agent), "shell_hook": "implemented", "mcp": "read_only_tools",
                        "native_enforcement": "not_verified", "native_version": "not_checked"}
                       for agent in AGENTS.values()], "other_clients": "generic_read_only_mcp_and_explicit_external_launch"}


def codex_command(python, launcher, online):
    argv = [str(python), "-I", str(launcher), "hook", "--agent", "codex", *(["--online"] if online else [])]
    if os.name != "nt":
        return "exec " + shlex.join(argv)
    # Codex invokes the configured user shell. A fixed system relay and encoded
    # literal argv avoid nested cmd/PowerShell interpolation of trusted paths.
    relay = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    if not re.fullmatch(r"[A-Za-z]:[A-Za-z0-9_./\\-]+", str(relay)) or not relay.is_file():
        raise ValueError("a trusted unambiguous system PowerShell relay is required")
    script = "& " + " ".join("'" + arg.replace("'", "''") + "'" for arg in argv) + "; exit $LASTEXITCODE"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return str(relay) + " -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded
