"""User-invoked pre-launch gate. This module is deliberately not an MCP tool.

The launcher enforces its own preflight decision before starting the selected
trusted client. It does not sandbox the client or freeze a mutable filesystem.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
from time import monotonic

from . import __version__
from . import git_startup
from .models import label
from .scanner import Scanner
from .filesystem import normalize_root

STARTUP_ENV = {
    "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONWARNINGS",
    "BASH_ENV", "ENV", "ZDOTDIR", "SHELLOPTS", "BASHOPTS", "RUBYOPT", "RUBYLIB",
    "PERL5OPT", "PERL5LIB", "LUA_INIT", "LUA_INIT_5_4", "LUA_PATH", "LUA_CPATH",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH", "DYLD_FALLBACK_LIBRARY_PATH",
    "GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EDITOR", "GIT_PAGER",
    "GIT_EXTERNAL_DIFF", "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR", "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
}
ANCESTOR_CONFIGS = (
    ".claude/settings.json", ".claude/settings.local.json", ".mcp.json",
    ".codex/hooks.json", ".codex/config.toml",
    ".cursor/mcp.json", ".cursor/hooks.json", ".gemini/settings.json", ".vscode/tasks.json",
)
MAX_PREFLIGHT_AGE = 300


def clean_environment(root: Path, environ: dict[str, str]) -> tuple[dict[str, str], list[str], int]:
    result = {key.upper(): value for key, value in environ.items()} if os.name == "nt" else dict(environ)
    for key in ("HOME", "XDG_CONFIG_HOME", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
        if not result.get(key):
            continue
        path = Path(result[key])
        if os.name == "nt":
            from .windows_files import local_path
            local_path(path)
        if not path.is_absolute() or path.resolve().is_relative_to(root):
            raise ValueError("global configuration points inside the untrusted project or uses a relative path")
    removed = sorted((STARTUP_ENV & result.keys()) | {k for k in result if k.startswith("BASH_FUNC_")})
    for key in removed:
        result.pop(key)
    if "GIT_CONFIG_COUNT" in result:
        count = result["GIT_CONFIG_COUNT"]
        if not count.isascii() or not count.isdigit() or len(count) > 3 or int(count) > 128:
            raise ValueError("unsupported Git environment configuration")
        pairs = []
        for index in range(int(count)):
            key_var, value_var = f"GIT_CONFIG_KEY_{index}", f"GIT_CONFIG_VALUE_{index}"
            if not result.get(key_var) or value_var not in result:
                raise ValueError("incomplete Git environment configuration")
            if git_startup.executable_override(result[key_var], result[value_var]):
                removed.extend((key_var, value_var))
            else:
                pairs.append((result[key_var], result[value_var]))
        for key in list(result):
            if key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
                result.pop(key)
        result["GIT_CONFIG_COUNT"] = str(len(pairs))
        for index, (key, value) in enumerate(pairs):
            result[f"GIT_CONFIG_KEY_{index}"] = key
            result[f"GIT_CONFIG_VALUE_{index}"] = value
    paths, dropped = [], 0
    for entry in result.get("PATH", os.defpath).split(os.pathsep):
        try:
            path = Path(entry)
            if not path.is_absolute():
                raise ValueError("relative PATH entry")
            path = normalize_root(path) if os.name == "nt" else path.resolve(strict=True)
            if not path.is_dir() or path.is_relative_to(root):
                raise ValueError("untrusted PATH entry")
        except (OSError, ValueError, RuntimeError):
            dropped += 1
            continue
        if str(path) not in paths:
            paths.append(str(path))
    if not paths:
        raise ValueError("no trusted absolute PATH entries")
    result["PATH"] = os.pathsep.join(paths)
    return result, sorted(set(removed)), dropped


def _identity(path: Path) -> tuple:
    info = path.lstat()
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns


def _inspect(root: Path, online: bool):
    report = Scanner(root, online=online).scan("standard")
    if not isinstance(report.snapshot_id, str) or len(report.snapshot_id) != 64:
        raise ValueError("scan did not establish a content fingerprint")
    findings, gaps, git_digest = git_startup.inspect(root)
    report.findings.extend(findings)
    for gap in gaps:
        report.gap(gap)
    # Fail closed on selected ancestor configuration outside the explicit root.
    # User-home/global configuration remains part of the trusted client setup.
    home = Path.home().resolve()
    if len(root.parents) > 64:
        report.gap("Ancestor inventory exceeds the launch scope budget")
    for ancestor in list(root.parents)[:64]:
        if ancestor == home:
            continue
        for relative in ANCESTOR_CONFIGS:
            try:
                (ancestor / relative).lstat()
                report.gap("Agent/editor configuration exists above the selected root; select a root that includes it")
            except FileNotFoundError:
                pass
            except OSError:
                report.gap("Ancestor configuration could not be checked")
        try:
            if not (root / ".git").exists() and (ancestor / ".git").exists():
                report.gap("Git metadata exists above the selected root; Git startup scope is incomplete")
        except OSError:
            report.gap("Ancestor Git metadata could not be checked")
    report.snapshot_id = hashlib.sha256(
        (__version__ + ":" + report.snapshot_id + ":" + git_digest).encode()).hexdigest()
    return report


def launch(root: Path, command: list[str], *, online=False, review=False, dry_run=False,
           input_stream=None, output_stream=None, receipt_formatter=None) -> int:
    input_stream = sys.stdin if input_stream is None else input_stream
    output_stream = sys.stderr if output_stream is None else output_stream

    def emit(**data):
        output_stream.write((receipt_formatter(data) if receipt_formatter else
                             json.dumps(data, separators=(",", ":"))) + "\n")
        output_stream.flush()

    try:
        if not sys.flags.isolated:
            raise ValueError("launch requires Python isolated mode")
        root = normalize_root(root)
        if not root.is_dir() or Path(__file__).resolve().is_relative_to(root):
            raise ValueError("scanner must be outside the inspected directory")
        if (not command or len(command) > 256 or not all(isinstance(a, str) and "\x00" not in a for a in command)
                or sum(len(a) for a in command) > 128 * 1024):
            raise ValueError("invalid launch command")
        executable = Path(command[0])
        if not executable.is_absolute():
            raise ValueError("an absolute client executable is required")
        executable = executable.resolve(strict=True)
        if os.name == "nt" and executable.suffix.lower() != ".exe":
            raise ValueError("Windows startup requires a native .exe client; batch shims are refused")
        if executable.is_relative_to(root) or not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("client executable must be trusted and outside the inspected root")
        argv = (str(executable), *command[1:])
        root_identity = _identity(root)[:3]
        executable_identity = _identity(executable)
        if not stat.S_ISDIR(root_identity[2]) or not stat.S_ISREG(executable_identity[2]):
            raise ValueError("root or executable changed into an indirect filesystem entry")
        environment, removed, dropped = clean_environment(root, os.environ)
        inspected_at = monotonic()
        report = _inspect(root, online)
        receipt = {"version": __version__, "agent": label(executable.name),
                   "scope": "standard_project_text_and_selected_git_startup",
                   "root_id": hashlib.sha256(str(root).encode()).hexdigest()[:16],
                   "command_id": hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                   "removed_startup_variables": removed, "dropped_path_entries": dropped,
                   "omitted_scopes": ["installed_and_generated_sources", "unrecognized_extensions", "trusted_global_client_configuration"],
                   "sandbox": "not_provided", "report": report.summary()}
        emit(decision=report.decision, execution="not_started", **receipt)
        if report.decision == "block":
            return 1
        if report.gaps or report.inventory == "incomplete" or report.advisories != "complete":
            return 2
        if report.decision != "no_findings":
            if dry_run or not review or not input_stream.isatty() or len(report.ordered()) > 50:
                return 2
            emit(review_findings=[f.detail() for f in report.ordered()], execution="not_started")
            challenge = "APPROVE " + secrets.token_hex(6)
            output_stream.write("Review challenge: " + challenge + "\n")
            output_stream.write("Type the challenge only after reviewing this snapshot; this is not sandbox approval.\n")
            output_stream.flush()
            # Bound input, do not accept piped/automatic yes responses or persist approval.
            if input_stream.readline(256).strip() != challenge:
                return 2
        if dry_run:
            return 0
        if monotonic() - inspected_at > MAX_PREFLIGHT_AGE:
            emit(decision="review", execution="not_started", reason="Preflight expired; inspect again before launching")
            return 2
        recheck = _inspect(root, False)  # Re-read content without a second network window.
        initial_static = {f.id for f in report.findings if f.evidence != "osv_version_match"}
        if (recheck.gaps or recheck.inventory == "incomplete" or recheck.snapshot_id != report.snapshot_id
                or {f.id for f in recheck.findings} != initial_static
                or _identity(root)[:3] != root_identity or _identity(executable) != executable_identity
                or monotonic() - inspected_at > MAX_PREFLIGHT_AGE):
            emit(decision="review", execution="not_started", reason="Project, configuration, root, or client changed; run preflight again")
            return 2
    except KeyboardInterrupt:
        return 130
    except Exception:
        emit(decision="error", execution="not_started",
             reason="Pre-launch check failed. Use Python -I, a trusted external scanner/client, and a readable project; no client was launched")
        return 3
    emit(decision="launch", execution="starting", snapshot_id=report.snapshot_id,
         sandbox="not_provided", review="interactive" if report.findings else "not_required")
    try:
        process = subprocess.run(argv, cwd=root, env=environment, shell=False, check=False)
        return process.returncode if process.returncode >= 0 else 128 - process.returncode
    except KeyboardInterrupt:
        return 130
    except OSError:
        emit(decision="error", execution="start_failed", reason="The selected client could not be executed")
        return 3
