"""Inventory selected execution surfaces without launching hooks or servers."""
from pathlib import PurePosixPath as Path
import tomllib

from . import jsondata
from .models import Finding

CONFIG_DIRS = {".vscode", ".claude", ".codex", ".cursor", ".gemini", ".github", ".agents"}
FORCED_NAMES = {".mcp.json", "mcp.json", "binding.gyp", "sitecustomize.py", "usercustomize.py"}


def inspect(path: str, text: str) -> tuple[list[Finding], list[str]]:
    p = Path(path)
    findings, gaps = [], []

    def add(rule, title, action):
        findings.append(Finding(rule, "medium", path, 1, title, action,
                                evidence="execution_surface", context="configuration"))

    if p.suffix == ".pth" and any(line.startswith(("import ", "import\t")) for line in text.splitlines()):
        add("PA403", "Python startup file executes import statements",
            "Review before this file enters a Python site-packages directory; scanning does not import it.")
    if p.name in {"sitecustomize.py", "usercustomize.py"}:
        add("PA406", "Python automatically imported startup module",
            "Review startup behavior before placing this module on a Python startup path.")
    if p.name == "binding.gyp":
        add("PA405", "Native build configuration can execute commands",
            "Review native build actions and isolate compilation before installing this package.")
    if p.name == "pyproject.toml":
        try:
            data = tomllib.loads(text)
            build = data.get("build-system", {})
            if not isinstance(build, dict):
                raise ValueError("invalid build configuration")
            if build.get("build-backend") or build.get("backend-path"):
                add("PA407", "Python build backend is executable configuration",
                    "Review backend requirements and local backend paths before building or installing source distributions.")
        except (ValueError, TypeError, AttributeError, RecursionError):
            gaps.append(f"Build configuration could not be inspected: {path}")
    codex_toml = ".codex" in p.parts and p.name == "config.toml"
    config = codex_toml or p.name in {".mcp.json", "mcp.json"} or (bool(set(p.parts) & CONFIG_DIRS)
               and p.name in {"settings.json", "settings.local.json", "hooks.json", "tasks.json"})
    if not config:
        return findings, gaps
    try:
        data = tomllib.loads(text) if codex_toml else jsondata.loads(text)
        if not isinstance(data, dict):
            raise ValueError("configuration must be an object")
        if codex_toml:
            features = data.get("features", {})
            if not isinstance(features, dict):
                raise ValueError("invalid Codex feature controls")
            for key in ("hooks", "codex_hooks"):
                if key in features and not isinstance(features[key], bool):
                    raise ValueError("invalid Codex hook control")
            if "allow_managed_hooks_only" in data and not isinstance(data["allow_managed_hooks_only"], bool):
                raise ValueError("invalid Codex managed hook control")
            if features.get("hooks") is False or features.get("codex_hooks") is False or data.get("allow_managed_hooks_only"):
                findings.append(Finding("PA409", "high", path, 1, "Codex configuration suppresses user hooks",
                    "Inspect the effective Codex settings and native hook trust; do not rely on user hooks under these controls.",
                    evidence="security_control_override", context="configuration"))
        if ".claude" in p.parts and p.name in {"settings.json", "settings.local.json"} and "disableAllHooks" in data:
            if not isinstance(data["disableAllHooks"], bool):
                raise ValueError("invalid hook-disable setting")
            if data["disableAllHooks"]:
                findings.append(Finding("PA408", "high", path, 1,
                    "Project configuration disables agent hooks",
                    "Do not rely on user-level guard hooks while this setting is active; inspect the client settings hierarchy.",
                    evidence="security_control_override", context="configuration"))
        if "hooks" in data:
            if not isinstance(data["hooks"], dict) or any(not isinstance(v, (dict, list)) for v in data["hooks"].values()):
                raise ValueError("unsupported hooks configuration")
            pending = [(data["hooks"], 0)]
            visited = 0
            while pending:
                item, depth = pending.pop()
                visited += 1
                if visited > 500 or depth > 12:
                    raise ValueError("hook configuration exceeds budget")
                if isinstance(item, dict):
                    if "type" in item and item["type"] not in {"command", "http", "mcp_tool", "prompt", "agent"}:
                        raise ValueError("unknown hook handler type")
                    if item.get("command"):
                        add("PA400", "Project lifecycle hook launches a command",
                            "Review this project hook before starting the agent; a Bash tool hook does not intercept lifecycle-hook execution.")
                    elif item.get("type") in {"http", "mcp_tool", "prompt", "agent"}:
                        add("PA404", "Project lifecycle hook invokes a tool, service, or model",
                            "Review the hook destination, permissions, and data access before activating this configuration.")
                    pending.extend((v, depth + 1) for v in item.values() if isinstance(v, (dict, list)))
                elif isinstance(item, list):
                    pending.extend((v, depth + 1) for v in item)
                elif not isinstance(item, (str, int, float, bool, type(None))):
                    raise ValueError("unsupported hook structure")
        for key in ("mcpServers", "servers", "mcp_servers"):
            if key not in data:
                continue
            servers = data[key]
            if not isinstance(servers, dict):
                raise ValueError("invalid MCP server configuration")
            for server in servers.values():
                if not isinstance(server, dict):
                    raise ValueError("invalid MCP server")
                if server.get("command"):
                    add("PA402", "Project configuration launches an MCP server",
                        "Inspect the server command statically before enabling it; this scan never starts the configured server.")
                elif server.get("url"):
                    add("PA404", "Project configuration connects to a remote MCP server",
                        "Review the server's trust and permissions before connecting; this scan does not contact it.")
        if p.name == "tasks.json":
            tasks = data.get("tasks", [])
            if not isinstance(tasks, list):
                raise ValueError("invalid editor tasks")
            for task in tasks:
                if not isinstance(task, dict) or not isinstance(task.get("runOptions", {}), dict):
                    raise ValueError("invalid editor task")
                if task.get("runOptions", {}).get("runOn") == "folderOpen":
                    add("PA109", "Editor task configured to run when a folder opens",
                        "Review the task before trusting this workspace in an editor.")
    except (ValueError, TypeError, AttributeError, RecursionError):
        gaps.append(f"Startup configuration malformed, unsupported, or over budget: {path}")
    # Do not repeat equivalent execution-surface warnings for every hook/server.
    return list({f.id: f for f in findings}.values()), gaps
