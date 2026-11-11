from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import time

from .dependencies import parse_inventory
from .filesystem import read_project_file
from .models import Report
from .rules import scan_text

ALWAYS_SKIP = {".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache", ".cache"}
INSTALLED = {"node_modules", ".venv", "venv", "vendor"}
GENERATED = {"dist", "build", "coverage", ".next"}
INVENTORIES = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "pyproject.toml", "uv.lock", "poetry.lock"}
UNSUPPORTED = {"yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "Pipfile", "Pipfile.lock", "pdm.lock", "setup.py", "setup.cfg"}
SUFFIXES = {".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".bash", ".ps1", ".php", ".rb", ".go", ".rs", ".json", ".toml", ".yaml", ".yml", ".md", ".txt", ".in", ".lock"}


def inventory(path: str) -> bool:
    name = Path(path).name
    return name in INVENTORIES or (name.startswith("requirements") and name.endswith((".txt", ".in")))


def selected(path: str, level: str) -> bool:
    p = Path(path)
    if p.name.startswith(".env") or p.suffix in {".key", ".pem", ".p12", ".pfx"}:
        return False
    if inventory(path) or p.name in UNSUPPORTED or p.name == ".npmrc":
        return True
    if level == "quick":
        return (p.name in {"AGENTS.md", "CLAUDE.md", "SKILL.md", "Makefile", "Dockerfile"}
                or any(part in {".vscode", ".claude", ".cursor", ".github", ".agents"} for part in p.parts)
                or "config" in p.name.lower() and p.suffix in SUFFIXES)
    return p.suffix in SUFFIXES or p.name in {"Makefile", "Dockerfile", ".bashrc"}


class Scanner:
    def __init__(self, root: Path, *, online: bool = False, osv_client=None,
                 max_files: int = 5000, max_bytes: int = 32 * 1024 * 1024,
                 max_seconds: float = 20):
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("scan root must be a directory")
        self.online = online
        self.osv_client = osv_client
        self.max_files = max_files
        self.max_bytes = max_bytes
        self.max_seconds = max_seconds
        self.cache = OrderedDict()

    def scan(self, level: str = "standard") -> Report:
        if level not in {"quick", "standard", "deep"}:
            raise ValueError("unknown scan level")
        report = Report(level, self.online)
        start = time.monotonic()
        paths = []
        entries = 0
        # Explicit stack bounds directory traversal too; os.walk first materializes
        # an entire directory and can consume unbounded memory in hostile trees.
        pending = [self.root]
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as children:
                    for entry in children:
                        entries += 1
                        if entries > self.max_files * 8 or time.monotonic() - start > self.max_seconds:
                            report.gap("Traversal budget exceeded; coverage is incomplete")
                            pending.clear()
                            break
                        relative = str(Path(entry.path).relative_to(self.root))
                        if entry.is_symlink():
                            report.gap(f"Symlink skipped: {relative}")
                        elif entry.is_dir(follow_symlinks=False):
                            if entry.name in ALWAYS_SKIP:
                                continue
                            if level != "deep" and entry.name in INSTALLED | GENERATED:
                                continue
                            pending.append(Path(entry.path))
                        elif selected(relative, level):
                            paths.append(relative)
                            if len(paths) > self.max_files:
                                report.gap("File count budget exceeded; coverage is incomplete")
                                pending.clear()
                                break
            except OSError:
                report.gap("A project directory could not be enumerated")
        paths = sorted(paths[:self.max_files], key=lambda p: (not inventory(p), p))
        contents = {}
        deps = []
        for relative in paths:
            if time.monotonic() - start > self.max_seconds:
                report.gap("Static scan time budget exceeded; coverage is incomplete")
                break
            cap = 8 * 1024 * 1024 if inventory(relative) else 1024 * 1024
            cap = min(cap, self.max_bytes - report.bytes_read)
            if cap <= 0:
                report.gap("Byte budget exceeded; coverage is incomplete")
                break
            try:
                raw = read_project_file(self.root, relative, cap)
                report.bytes_read += len(raw)
                report.files += 1
                if b"\x00" in raw:
                    report.gap(f"Binary content in selected file: {relative}")
                    continue
                text = raw.decode("utf-8-sig")
            except (OSError, UnicodeError):
                report.gap(f"Selected file unreadable, oversized, or non-UTF8: {relative}")
                continue
            contents[relative] = text
            digest = hashlib.sha256(raw).hexdigest()
            key = (relative, digest)
            if key in self.cache:
                report.findings.extend(self.cache[key])
                report.cached_files += 1
                self.cache.move_to_end(key)
            else:
                hits = scan_text(relative, text)
                self.cache[key] = hits
                report.findings.extend(hits)
                if len(self.cache) > self.max_files:
                    self.cache.popitem(last=False)
            if Path(relative).name in UNSUPPORTED:
                report.gap(f"Unsupported dependency inventory: {relative}")

        from .dependencies import public_registry
        npm_public = all(public_registry(match[1].strip(), "npm")
            for path, text in contents.items() if Path(path).name == ".npmrc"
            for match in re.finditer(r"(?im)^\s*(?:@[^:\s]+:)?registry\s*=\s*(\S+)", text))
        for relative, text in contents.items():
            if inventory(relative):
                deps.extend(parse_inventory(relative, text, report, npm_public))
            if Path(relative).name == "package.json" and "node_modules" not in Path(relative).parts:
                parent = str(Path(relative).parent)
                sibling_locks = {str(Path(parent) / name) for name in ("package-lock.json", "npm-shrinkwrap.json")}
                # A monorepo may be covered by a root lock; no reachability assertion.
                if not (sibling_locks & contents.keys()) and not any(p in contents for p in ("package-lock.json", "npm-shrinkwrap.json")):
                    report.gap(f"npm project lacks a supported transitive lockfile: {relative}")
            if Path(relative).name == "pyproject.toml":
                parent = Path(relative).parent
                if not any(str(parent / name) in contents for name in ("uv.lock", "poetry.lock")):
                    report.gap(f"Python project lacks a supported transitive lockfile: {relative}")
        locked = {(d.ecosystem, d.name, d.version) for d in deps
                  if Path(d.path).name in {"package-lock.json", "npm-shrinkwrap.json", "uv.lock", "poetry.lock"}}
        unique = sorted({d for d in deps if not (Path(d.path).name in {"package.json", "pyproject.toml"}
                        and (d.ecosystem, d.name, d.version) in locked)})
        report.dependencies = len({(d.ecosystem, d.name, d.version) for d in unique})
        if self.online:
            if self.osv_client is None:
                from .osv import OSVClient
                self.osv_client = OSVClient()
            self.osv_client.check(unique, report)
            if report.advisories == "complete":
                report.advisory_checked_at = datetime.now(timezone.utc).isoformat()
        return report
