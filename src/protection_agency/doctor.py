"""Offline diagnostics. Self-checks do not prove that an agent installed a hook."""
import json
import os
from pathlib import Path
import sys
import tempfile

from . import __version__
from .policy import check_command
from .rules import scan_text
from .scanner import Scanner
from .startup import inspect
from .filesystem import normalize_root


def diagnose(root: Path | None = None, *, settings: Path | None = None, probe_hooks=False, agent="claude") -> dict:
    checks = []

    def add(name, passed):
        checks.append({"check": name, "status": "passed" if passed else "failed"})

    add("python_3_11_or_newer", sys.version_info >= (3, 11))
    add("secure_platform_file_reads", os.name == "nt" or (hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd))
    add("known_malicious_install_classified_deny", check_command("npm install cdeops@13.5.31")["decision"] == "deny")
    documentation = scan_text("README.md", "Inert example: eval(atob('example'))")
    add("documentation_keeps_review_context", bool(documentation) and all(f.severity == "low" for f in documentation))
    hits, gaps = inspect(".claude/settings.json", json.dumps({"hooks": {"SessionStart": [
        {"hooks": [{"type": "command", "command": "echo inert-example"}]}]}}))
    add("startup_command_identified", not gaps and any(f.rule == "PA400" for f in hits))
    with tempfile.TemporaryDirectory(prefix="protection-agency-doctor-") as temporary:
        fixture = Path(temporary)
        (fixture / "package.json").write_text('{"dependencies":{"example":"^1.0.0"}}')
        (fixture / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{"":{}}}')
        report = Scanner(fixture).scan("quick")
        add("missing_lock_entry_reported", report.inventory == "incomplete" and bool(report.gaps))
    warnings = []
    if not sys.flags.isolated:
        warnings.append("Use the trusted launcher with Python -I to isolate Python startup")
    if root is not None:
        root = normalize_root(root)
        if not root.is_dir():
            raise ValueError("root must be a directory")
        if Path(__file__).resolve().is_relative_to(root):
            warnings.append("Scanner is inside the inspected root; use a trusted installation outside untrusted projects")
    integration = None
    if settings is not None:
        if root is None:
            raise ValueError("configuration inspection requires an explicit project root")
        from .integration import inspect_configuration
        integration = inspect_configuration(settings, root, probe=probe_hooks, agent=agent)
        add(agent + "_user_hook_configuration", integration["status"] == "configured")
        if probe_hooks:
            add("trusted_hook_protocol_probe", integration["probe"] == "passed")
    result = {"version": __version__, "status": "failed" if any(c["status"] == "failed" for c in checks) else "self_checks_passed",
            "checks": checks, "warnings": warnings, "live_client_enforcement": "not_verified",
            "note": "Offline checks only. Optional configuration/protocol checks do not verify native client loading, hook order/timeouts, sandboxing, or startup interception."}
    if integration is not None:
        result["integration"] = integration
    return result
