"""A deliberately small command policy, not a general shell parser or sandbox."""
import re
import shlex

from .rules import scan_text


def check_command(command: str) -> dict:
    if not isinstance(command, str) or not command.strip() or len(command) > 32768:
        return {"decision": "deny", "reason": "Missing or oversized command"}
    hits = [f for f in scan_text("<command>", command) if f.severity in {"high", "critical"}]
    if hits:
        return {"decision": "deny", "reason": hits[0].title,
                "rules": [f.rule for f in hits]}
    if re.search(r"(?:powershell|pwsh)\b[^\n]{0,300}-(?:enc|encodedcommand)\b", command, re.I):
        return {"decision": "deny", "reason": "Encoded PowerShell execution requires separate inspection"}
    # Never classify shell composition, expansion, redirection, escaping, globbing,
    # or command substitution as a simple read. Unknown syntax requires review.
    if not re.fullmatch(r"[A-Za-z0-9_./\-\s]+", command) or "\n" in command or "\r" in command:
        return {"decision": "ask", "reason": "Shell composition or unsupported syntax requires review"}
    try:
        words = shlex.split(command)
    except ValueError:
        return {"decision": "deny", "reason": "Malformed command"}
    if words == ["pwd"] or words in (["rg", "--files"], ["rg", "--files", "."]):
        return {"decision": "no_objection", "reason": "Simple read operation; normal agent permissions still apply"}
    if words and words[0] == "ls" and all(not w.startswith("-") or w in {"-l", "-a", "-la", "-al", "--"} for w in words[1:]):
        return {"decision": "no_objection", "reason": "Simple directory listing; normal agent permissions still apply"}
    return {"decision": "ask", "reason": "Execution, installation, or an unrecognized command requires review"}
