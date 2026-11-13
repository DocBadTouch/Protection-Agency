"""User-invoked Claude hook setup and bounded diagnostics; no native client starts."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from . import config_io, jsondata
from .filesystem import read_project_file
from .launcher import clean_environment

MARKER = "Protection Agency security check"
MINIMUM_CLIENT = "2.1.295"
EVENTS = ("SessionStart", "PreToolUse")


def _locations(settings: Path, project: Path):
    if os.name != "posix":
        raise ValueError("configuration integration requires POSIX file protections")
    settings, project = Path(settings), Path(project).resolve(strict=True)
    if (not settings.is_absolute() or ".." in settings.parts or not project.is_dir()
            or settings.is_relative_to(project) or len(settings.name) > 128):
        raise ValueError("choose an absolute user settings file outside the project")
    python = Path(sys.executable).resolve(strict=True)
    launcher = (Path(__file__).resolve().parents[2] / "guard.py").resolve(strict=True)
    if (python.is_relative_to(project) or launcher.is_relative_to(project)
            or not python.is_file() or not os.access(python, os.X_OK) or not launcher.is_file()):
        raise ValueError("use a trusted external Python and source installation")
    return settings, project, python, launcher


def _handler(event: str, python: Path, launcher: Path, online: bool):
    result = {"type": "command", "command": str(python),
              "args": ["-I", str(launcher), "hook", *(["--online"] if online else [])],
              "timeout": 90, "statusMessage": MARKER}
    if event == "PreToolUse":
        result["onFailure"] = "block"
    return result


def _load(settings: Path):
    fd = config_io.open_parent(settings.parent)
    try:
        snapshot = config_io.read(fd, settings.name)
    finally:
        if fd is not None:
            os.close(fd)
    if snapshot.raw is None:
        return {}, snapshot
    data = jsondata.loads(snapshot.raw.decode("utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("hooks", {}), dict):
        raise ValueError("unsupported settings structure")
    for groups in data.get("hooks", {}).values():
        if not isinstance(groups, list):
            raise ValueError("unsupported event structure")
        for group in groups:
            if (not isinstance(group, dict) or not isinstance(group.get("hooks"), list)
                    or "matcher" in group and not isinstance(group["matcher"], str)
                    or not all(isinstance(h, dict) for h in group["hooks"])):
                raise ValueError("unsupported hook group")
    if "disableAllHooks" in data and not isinstance(data["disableAllHooks"], bool):
        raise ValueError("invalid hook-disable setting")
    return data, snapshot


def _legacy(handler, event, python, launcher):
    for online in (False, True):
        expected = _handler(event, python, launcher, online)
        expected.pop("statusMessage")
        if handler == expected:
            return True
    return False


def _strip(data, python, launcher):
    result = copy.deepcopy(data)
    removed = 0
    for event, groups in list(result.get("hooks", {}).items()):
        kept_groups = []
        removed_in_event = 0
        for group in groups:
            kept = []
            removed_in_group = 0
            for handler in group["hooks"]:
                if handler.get("statusMessage") == MARKER or (
                        event in EVENTS and _legacy(handler, event, python, launcher)):
                    removed += 1
                    removed_in_event += 1
                    removed_in_group += 1
                else:
                    kept.append(handler)
            if not removed_in_group or kept or set(group) - {"matcher", "hooks"}:
                kept_groups.append({**group, "hooks": kept})
        if kept_groups or not removed_in_event:
            result["hooks"][event] = kept_groups
        else:
            result["hooks"].pop(event)
    if removed and not result.get("hooks"):
        result.pop("hooks", None)
    return result, removed


def configure(operation: str, settings: Path, project: Path, *, online=False, dry_run=False,
              expected_snapshot=None) -> dict:
    if operation not in {"install", "uninstall"}:
        raise ValueError("unknown setup operation")
    if not sys.flags.isolated:
        raise ValueError("run trusted setup with Python -I")
    settings, project, python, launcher = _locations(settings, project)
    data, snapshot = _load(settings)
    common = {"client": "claude", "scope": "user_settings_Bash_only", "live_client_enforcement": "not_verified",
              "minimum_client_version": MINIMUM_CLIENT, "client_version": "not_checked"}
    if expected_snapshot is not None and snapshot != expected_snapshot:
        return {**common, "status": "conflict", "changed": False,
                "reason": "Settings changed after preview; inspect them and run setup again"}
    if operation == "install" and data.get("disableAllHooks") is True:
        return {**common, "status": "disabled", "changed": False,
                "reason": "Settings explicitly disable hooks; setup will not change that choice"}
    if operation == "install" and _project_controls(project):
        return {**common, "status": "disabled_by_project", "changed": False,
                "reason": "Project settings contain disableAllHooks; inspect the control before installing hooks"}
    updated, removed = _strip(data, python, launcher)
    if operation == "install":
        hooks = updated.setdefault("hooks", {})
        for event in EVENTS:
            group = {"hooks": [_handler(event, python, launcher, online)]}
            if event == "PreToolUse":
                group["matcher"] = "Bash"
            hooks.setdefault(event, []).append(group)
    elif not removed:
        return {**common, "status": "not_installed", "changed": False}
    if updated == data and snapshot.identity is not None and snapshot.identity[2] & 0o777 == 0o600:
        return {**common, "status": "already_installed" if operation == "install" else "not_installed", "changed": False}
    raw = (json.dumps(updated, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    if len(raw) > config_io.LIMIT:
        raise ValueError("new configuration exceeds the read budget")
    if dry_run:
        return {**common, "status": "would_" + operation, "changed": False,
                "backup_required": snapshot.raw is not None, "normalizes_json": True,
                "managed_events": list(EVENTS), "online": bool(online)}
    result = config_io.replace(settings, snapshot, raw)
    if result["status"] == "applied":
        result["status"] = "installed" if operation == "install" else "uninstalled"
    return {**common, **result, "normalizes_json": True,
            "configuration_sha256": hashlib.sha256(raw).hexdigest() if result["changed"] else None}


def _project_controls(project):
    for relative in (".claude/settings.json", ".claude/settings.local.json"):
        try:
            raw = read_project_file(project, relative, config_io.LIMIT)
        except FileNotFoundError:
            continue
        data = jsondata.loads(raw.decode("utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("invalid project configuration")
        if "disableAllHooks" in data:
            if not isinstance(data["disableAllHooks"], bool):
                raise ValueError("invalid project hook-disable control")
            if data["disableAllHooks"]:
                return True
    return False


def probe_protocol(project, python, launcher, *, online=False):
    """Exercise only reconstructed trusted hook argv with inert, offline events."""
    if not sys.flags.isolated:
        raise ValueError("run trusted hook probes with Python -I")
    handler = _handler("PreToolUse", python, launcher, online)
    environment, _, _ = clean_environment(project, os.environ)
    cases = [
        ("known_malicious_install_denied", {"hook_event_name": "PreToolUse", "cwd": str(project),
         "tool_name": "Bash", "tool_input": {"command": "npm install cdeops@13.5.31"}}, "deny"),
        ("simple_read_keeps_native_permissions", {"hook_event_name": "PreToolUse", "cwd": str(project),
         "tool_name": "Bash", "tool_input": {"command": "pwd"}}, "no_decision"),
        ("malformed_event_rejected", {}, "exit_two"),
    ]
    checks = []
    for name, event, expected in cases:
        process = subprocess.run([handler["command"], *handler["args"]], input=json.dumps(event),
                                 capture_output=True, text=True, cwd=project, env=environment, timeout=5, shell=False)
        if len(process.stdout) > 65536 or len(process.stderr) > 65536:
            raise ValueError("unexpected probe output")
        if expected == "exit_two":
            valid = process.returncode == 2
        else:
            output = json.loads(process.stdout)
            valid = process.returncode == 0 and isinstance(output, dict) and (
                output == {} if expected == "no_decision" else
                output.get("hookSpecificOutput", {}).get("permissionDecision") == expected)
        checks.append({"check": name, "status": "passed" if valid else "failed"})
        if not valid:
            break
    return checks


def inspect_configuration(settings: Path, project: Path, *, probe=False) -> dict:
    result = {"status": "unsafe_or_invalid", "probe": "not_run", "client": "claude",
              "scope": "user_settings_Bash_only", "minimum_client_version": MINIMUM_CLIENT,
              "client_version": "not_checked", "live_client_enforcement": "not_verified"}
    try:
        settings, project, python, launcher = _locations(settings, project)
        data, snapshot = _load(settings)
        if snapshot.raw is None:
            return {**result, "status": "missing"}
        if data.get("disableAllHooks") is True:
            return {**result, "status": "disabled"}
        if _project_controls(project):
            return {**result, "status": "disabled_by_project"}
        found = []
        legacy = False
        for event, groups in data.get("hooks", {}).items():
            for group in groups:
                for handler in group["hooks"]:
                    if handler.get("statusMessage") == MARKER:
                        found.append((event, group, handler))
                    elif event in EVENTS and _legacy(handler, event, python, launcher):
                        legacy = True
        if not found:
            return {**result, "status": "manual_configuration" if legacy else "missing"}
        modes = []
        if len(found) != 2 or {event for event, _, _ in found} != set(EVENTS):
            return {**result, "status": "modified"}
        for event, group, handler in found:
            valid_mode = next((mode for mode in (False, True) if handler == _handler(event, python, launcher, mode)), None)
            expected_group = {"hooks": [handler]}
            if event == "PreToolUse":
                expected_group["matcher"] = "Bash"
            if valid_mode is None or group != expected_group:
                return {**result, "status": "modified"}
            modes.append(valid_mode)
        if len(set(modes)) != 1:
            return {**result, "status": "modified"}
        result.update(status="configured", online=modes[0], configuration_sha256=hashlib.sha256(snapshot.raw).hexdigest())
        if probe:
            if not sys.flags.isolated:
                return {**result, "probe": "requires_isolated_python"}
            checks = probe_protocol(project, python, launcher, online=modes[0])
            if len(checks) != 3 or any(c["status"] != "passed" for c in checks):
                return {**result, "probe": "failed"}
            if _load(settings)[1] != snapshot:
                return {**result, "status": "changed_during_check", "probe": "not_verified"}
            result["probe"] = "passed"
        return result
    except (OSError, ValueError, TypeError, AttributeError, RecursionError, subprocess.TimeoutExpired):
        return {**result, "status": "check_failed" if result["status"] == "configured" else "unsafe_or_invalid",
                "probe": "failed" if result["status"] == "configured" and probe else "not_run"}
