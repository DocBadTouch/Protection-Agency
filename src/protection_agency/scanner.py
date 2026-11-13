from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import time

from .dependencies import parse_inventory
from .coverage import audit_inventories
from .filesystem import read_project_file
from .models import Report
from .rules import scan_text
from .startup import CONFIG_DIRS, FORCED_NAMES, inspect as inspect_startup

ALWAYS_SKIP = {".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache", ".cache"}
INSTALLED = {"node_modules", ".venv", "venv", "vendor"}
GENERATED = {"dist", "build", "coverage", ".next"}
INVENTORIES = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "pyproject.toml", "uv.lock", "poetry.lock"}
UNSUPPORTED = {"yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "Pipfile", "Pipfile.lock", "pdm.lock", "setup.py", "setup.cfg"}
SUFFIXES = {".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".bash", ".ps1", ".php", ".rb", ".go", ".rs", ".json", ".jsonc", ".toml", ".yaml", ".yml", ".md", ".mdc", ".rst", ".txt", ".in", ".lock", ".pth", ".gyp"}


def inventory(path: str) -> bool:
    name = Path(path).name
    return name in INVENTORIES or (name.startswith("requirements") and name.endswith((".txt", ".in")))


def selected(path: str, level: str) -> bool:
    p = Path(path)
    if p.name.startswith(".env") or p.suffix in {".key", ".pem", ".p12", ".pfx"}:
        return False
    if inventory(path) or p.name in UNSUPPORTED | FORCED_NAMES | {".npmrc"} or p.suffix == ".pth":
        return True
    quick = (p.name in {"AGENTS.md", "CLAUDE.md", "SKILL.md", "Makefile", "Dockerfile"}
             or bool(set(p.parts) & CONFIG_DIRS)
             or "config" in p.name.lower() and p.suffix in SUFFIXES)
    return quick or (level != "quick" and (p.suffix in SUFFIXES or p.name == ".bashrc"))


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
                            report.inventory_gap("Traversal budget exceeded; coverage is incomplete")
                            pending.clear()
                            break
                        relative = str(Path(entry.path).relative_to(self.root))
                        if entry.is_symlink():
                            report.gap(f"Symlink skipped: {relative}")
                            if inventory(relative) or entry.is_dir():
                                report.inventory = "incomplete"
                        elif entry.is_dir(follow_symlinks=False):
                            if entry.name in ALWAYS_SKIP:
                                continue
                            if level != "deep" and entry.name in INSTALLED | GENERATED:
                                continue
                            pending.append(Path(entry.path))
                        elif selected(relative, level):
                            paths.append(relative)
                            if len(paths) > self.max_files:
                                report.inventory_gap("File count budget exceeded; coverage is incomplete")
                                pending.clear()
                                break
            except OSError:
                report.inventory_gap("A project directory could not be enumerated")
        paths = sorted(paths[:self.max_files], key=lambda p: (not inventory(p), p))
        if report.inventory != "incomplete" and any(inventory(p) for p in paths):
            report.inventory = "complete"
        contents = {}
        deps = []
        for relative in paths:
            if time.monotonic() - start > self.max_seconds:
                report.inventory_gap("Static scan time budget exceeded; coverage is incomplete")
                break
            cap = 8 * 1024 * 1024 if inventory(relative) else 1024 * 1024
            cap = min(cap, self.max_bytes - report.bytes_read)
            if cap <= 0:
                report.inventory_gap("Byte budget exceeded; coverage is incomplete")
                break
            try:
                raw = read_project_file(self.root, relative, cap)
                report.bytes_read += len(raw)
                report.files += 1
                if b"\x00" in raw:
                    report.gap(f"Binary content in selected file: {relative}")
                    if inventory(relative):
                        report.inventory = "incomplete"
                    continue
                text = raw.decode("utf-8-sig")
            except (OSError, UnicodeError):
                report.gap(f"Selected file unreadable, oversized, or non-UTF8: {relative}")
                if inventory(relative):
                    report.inventory = "incomplete"
                continue
            contents[relative] = text
            digest = hashlib.sha256(raw).hexdigest()
            key = (relative, digest)
            if key in self.cache:
                hits, gaps = self.cache[key]
                report.cached_files += 1
                self.cache.move_to_end(key)
            else:
                hits = scan_text(relative, text)
                startup_hits, gaps = inspect_startup(relative, text)
                hits.extend(startup_hits)
                self.cache[key] = (hits, gaps)
                if len(self.cache) > self.max_files:
                    self.cache.popitem(last=False)
            report.findings.extend(hits)
            for gap in gaps:
                report.gap(gap)
            if Path(relative).name in UNSUPPORTED:
                report.inventory_gap(f"Unsupported dependency inventory: {relative}")

        from .dependencies import public_registry
        npm_public = all(public_registry(match[1].strip(), "npm")
            for path, text in contents.items() if Path(path).name == ".npmrc"
            for match in re.finditer(r"(?im)^\s*(?:@[^:\s]+:)?registry\s*=\s*(\S+)", text))
        for relative, text in contents.items():
            if inventory(relative):
                locked = any(str(Path(relative).parent / name) in contents for name in ("uv.lock", "poetry.lock"))
                deps.extend(parse_inventory(relative, text, report, npm_public, locked))
        audit_inventories(contents, deps, report)
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
