"""Bounded launch-only Git metadata inspection. Never runs Git or a helper."""
import configparser
import hashlib
import json
import os
from pathlib import Path
import stat

from .filesystem import directory_entries, read_project_file
from .models import Finding

EXECUTION_KEYS = {
    "core": {"fsmonitor", "hookspath", "sshcommand", "pager", "editor"},
    "credential": {"helper"}, "filter": {"clean", "smudge", "process"},
    "diff": {"command", "textconv", "external"}, "merge": {"driver"},
    "gpg": {"program", "ssh.program", "x509.program"},
    "pager": None, "sequence": {"editor"}, "protocol": {"allow"},
}


def executable_override(name: str, value: str) -> bool:
    """Classify known Git environment config keys without exposing their values."""
    parts = name.lower().split(".")
    family, key = parts[0], parts[-1]
    return (family in {"include", "includeif"}
            or family in EXECUTION_KEYS and (EXECUTION_KEYS[family] is None or key in EXECUTION_KEYS[family])
            or family == "alias" and value.lstrip().startswith("!")
            or family == "submodule" and key == "update" and value.lstrip().startswith("!")
            or family == "remote" and key == "url" and value.lstrip('"').startswith("ext::"))


def inspect(root: Path) -> tuple[list[Finding], list[str], str]:
    findings, gaps, records = [], [], []
    metadata = root / ".git"
    try:
        info = metadata.lstat()
    except FileNotFoundError:
        return [], [], hashlib.sha256(b"no-root-git-metadata").hexdigest()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        return [], ["Root .git is indirect or symlinked; Git startup scope is incomplete"], "incomplete"
    for name in ("commondir", "config.worktree"):
        try:
            (metadata / name).lstat()
            gaps.append("Shared/per-worktree Git configuration is outside the launch inventory")
        except FileNotFoundError:
            pass
        except OSError:
            gaps.append("Git configuration layout could not be inspected")

    def add(rule, path, title):
        findings.append(Finding(rule, "medium", path, 1, title,
            "Review this Git execution surface before launching the client. This inspection never runs Git or its hooks.",
            evidence="execution_surface", context="configuration"))

    try:
        raw = read_project_file(root, ".git/config", 256 * 1024)
        records.append((".git/config", hashlib.sha256(raw).hexdigest()))
        config = configparser.RawConfigParser(strict=True, allow_no_value=True)
        config.optionxform = str.lower
        config.read_string(raw.decode("utf-8-sig"))
        for section in config.sections():
            family = section.lower().split()[0]
            if family in {"include", "includeif"}:
                gaps.append("Git configuration includes are not followed; startup scope is incomplete")
            for key, value in config.items(section):
                value = value or ""
                if family == "core" and key == "hookspath":
                    gaps.append("Custom Git hooksPath is not followed; startup scope is incomplete")
                if family == "extensions" and key == "worktreeconfig":
                    gaps.append("Per-worktree Git settings require separate inventory")
                if executable_override(family + "." + key, value):
                    add("PA500", ".git/config", "Git configuration declares an executable helper")
    except (OSError, UnicodeError, configparser.Error, ValueError):
        gaps.append("Git configuration could not be inspected; startup scope is incomplete")
    try:
            with directory_entries(root, ".git/hooks") as entries:
                for index, entry in enumerate(entries):
                    if index >= 128:
                        gaps.append("Git hook inventory exceeded its budget")
                        break
                    if entry.name.endswith(".sample"):
                        continue
                    path = ".git/hooks/" + entry.name
                    try:
                        mode = entry.stat(follow_symlinks=False).st_mode
                        raw = read_project_file(root, path, 64 * 1024)
                        records.append((path, hashlib.sha256(raw).hexdigest(), mode))
                        if mode & 0o111 or os.name == "nt":
                            add("PA501", path, "Executable Git hook present")
                    except OSError:
                        gaps.append("A Git hook file could not be inspected; startup scope is incomplete")
    except FileNotFoundError:
        pass
    except OSError:
        gaps.append("Git hook directory could not be inspected; startup scope is incomplete")
    digest = hashlib.sha256(json.dumps(sorted(records), separators=(",", ":")).encode()).hexdigest()
    return list({f.id: f for f in findings}.values()), list(dict.fromkeys(gaps)), digest
