"""Claude Code command hooks; policy code must live outside the target repository."""
import json
from pathlib import Path
import sys

from .policy import check_command
from .preflight import check_dependencies, command_targets
from .scanner import Scanner

MAX_INPUT = 1024 * 1024


def deny(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
            "permissionDecision": "deny", "permissionDecisionReason": reason}}


def handle(event: dict, *, online: bool = False, agent="claude") -> dict:
    from .agents import get_agent
    get_agent(agent)
    output = _handle(event, online=online)
    if agent == "codex" and output.get("hookSpecificOutput", {}).get("permissionDecision") == "ask":
        return deny("Protection Agency requires review of this execution. The Codex adapter cannot request native 'ask'; this command is denied. Inspect the standalone findings and keep sandboxing enabled.")
    return output


def _handle(event: dict, *, online: bool = False) -> dict:
    if not isinstance(event, dict):
        raise ValueError("hook input must be an object")
    kind = event.get("hook_event_name")
    if kind not in {"SessionStart", "PreToolUse"}:
        raise ValueError("unsupported hook event")
    cwd = event.get("cwd")
    if not isinstance(cwd, str) or not Path(cwd).is_absolute():
        raise ValueError("hook requires an absolute cwd")
    if kind == "PreToolUse":
        if event.get("tool_name") != "Bash":
            return deny("This hook supports Bash only; configure a dedicated adapter for other execution tools")
        tool_input = event.get("tool_input")
        if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command"), str):
            raise ValueError("Bash hook requires a command")
        verdict = check_command(tool_input["command"])
        if verdict["decision"] == "deny":
            return deny("Protection Agency: " + verdict["reason"])
        if verdict["decision"] == "no_objection":
            return {}  # No allow decision: other permission checks retain control.
        targets = command_targets(tool_input["command"])
        target_results = check_dependencies(targets, online=online)
        for result in target_results:
            if result["decision"] == "block":
                return deny("Protection Agency: known malicious proposed dependency; inspect its release advisory before execution.")
    report = Scanner(Path(cwd), online=online).scan("standard")
    if kind == "SessionStart":
        # SessionStart supplies context; it cannot block execution.
        return {"hookSpecificOutput": {"hookEventName": "SessionStart",
            "additionalContext": "Protection Agency screening: " + json.dumps(report.summary(limit=3), separators=(",", ":"))}}
    reason = f"Protection Agency: {len(report.ordered())} project findings; project advisories {report.advisories}. "
    if targets:
        states = ",".join(sorted({r["coverage"]["advisories"] for r in target_results}))
        reason += f"Proposed-release advisories {states}; transitive packages and artifacts not checked. "
    if report.decision == "block":
        top = report.ordered()[0]
        return deny(reason + top.title + ". Inspect with the standalone scanner before executing project code.")
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
            "permissionDecisionReason": reason + "Review this command and run project code in a sandbox."}}


def run(*, online: bool = False, agent="claude") -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError("hook input exceeds budget")
        output = handle(json.loads(raw), online=online, agent=agent)
        print(json.dumps(output, separators=(",", ":")))
        return 0
    except Exception:
        if agent == "codex":
            print(json.dumps(deny("Protection Agency could not complete its check; this tool call is denied."), separators=(",", ":")))
            return 0
        # Do not echo target data or exception strings that may contain secrets.
        print("Protection Agency could not complete its hook check; execution blocked.", file=sys.stderr)
        return 2
