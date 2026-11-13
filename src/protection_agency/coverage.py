"""Check inventory relationships as data; never invoke a package resolver."""
import json
from pathlib import PurePosixPath as Path
import tomllib

from .constraints import python_requirement, satisfies
from .models import Report

NPM_LOCKS = {"package-lock.json", "npm-shrinkwrap.json"}
SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def _npm_entry(packages: dict, location: str, name: str) -> dict | None:
    current = Path(location)
    while True:
        candidate = str(current / "node_modules" / name)
        if candidate in packages:
            item = packages[candidate]
            return item if isinstance(item, dict) else None
        if str(current) == ".":
            return None
        current = current.parent
        # Node skips redundant node_modules/node_modules lookup paths.
        if current.name == "node_modules":
            current = current.parent


def audit_inventories(contents: dict[str, str], dependencies: list, report: Report) -> None:
    parsed = {}
    for path, text in contents.items():
        name = Path(path).name
        if name in NPM_LOCKS | {"package.json", "pyproject.toml", "uv.lock", "poetry.lock"}:
            try:
                data = json.loads(text) if name.endswith(".json") else tomllib.loads(text)
                if not isinstance(data, dict):
                    raise ValueError("inventory must be an object")
                parsed[path] = data
            except (ValueError, TypeError, RecursionError):
                report.inventory_gap(f"Malformed or unsupported inventory: {path}")

    npm_locks = {p: d["packages"] for p, d in parsed.items()
                 if Path(p).name in NPM_LOCKS and d.get("lockfileVersion") in {2, 3}
                 and isinstance(d.get("packages"), dict)}

    def check_declarations(path, packages, location, declarations):
        for section in (*SECTIONS, "peerDependencies"):
            # Registry packages' development dependencies are not consumer installs.
            if section == "devDependencies" and "node_modules" in Path(location).parts:
                continue
            values = declarations.get(section, {})
            if not isinstance(values, dict):
                report.inventory_gap(f"Malformed npm dependency declarations: {path}")
                continue
            for name, spec in values.items():
                if not isinstance(name, str) or not name or not isinstance(spec, str):
                    report.inventory_gap(f"Malformed npm dependency declaration: {path}")
                    continue
                item = _npm_entry(packages, location, name)
                if item is None:
                    peer_meta = declarations.get("peerDependenciesMeta", {})
                    optional = (peer_meta.get(name, {}) if isinstance(peer_meta, dict) else {})
                    if section == "peerDependencies" and isinstance(optional, dict) and optional.get("optional"):
                        continue
                    report.inventory_gap(f"npm dependency missing from lock entries: {path}")
                    continue
                if item.get("link"):
                    report.inventory_gap(f"Linked npm dependency requires separate review: {path}")
                    continue
                match = satisfies(item.get("version", ""), spec, "npm")
                if match is False:
                    report.inventory_gap(f"npm locked version conflicts with its declaration: {path}")
                elif match is None:
                    report.inventory_gap(f"Unsupported npm dependency selector requires review: {path}")

    for path, packages in npm_locks.items():
        for location, entry in packages.items():
            if not isinstance(location, str) or not isinstance(entry, dict):
                report.inventory_gap(f"Malformed npm lock entry: {path}")
                continue
            check_declarations(path, packages, location, entry)

    for path, data in parsed.items():
        parent = Path(path).parent
        if Path(path).name == "package.json" and "node_modules" not in parent.parts:
            found = None
            for ancestor in (parent, *parent.parents):
                for name in ("npm-shrinkwrap.json", "package-lock.json"):
                    lock = str(ancestor / name)
                    location = str(parent.relative_to(ancestor))
                    location = "" if location == "." else location
                    if lock in npm_locks and isinstance(npm_locks[lock].get(location), dict):
                        found = lock, npm_locks[lock], location
                        break
                if found:
                    break
            if found:
                lock, packages, location = found
                recorded = packages[location]
                if any(data.get(s, {}) != recorded.get(s, {}) for s in SECTIONS):
                    report.inventory_gap(f"npm manifest and lock declarations differ: {path}")
                check_declarations(path, packages, location, data)
            elif any(data.get(s) for s in SECTIONS):
                report.inventory_gap(f"npm manifest is not represented by a supported lockfile: {path}")
        elif Path(path).name == "pyproject.toml":
            project = data.get("project", {})
            try:
                specs = list(project.get("dependencies", []))
                if not isinstance(project.get("dependencies", []), list):
                    raise ValueError("invalid project dependencies")
                groups = project.get("optional-dependencies", {})
                for group in groups.values():
                    if not isinstance(group, list):
                        raise ValueError("invalid optional dependencies")
                    specs.extend(group)
                for group in data.get("dependency-groups", {}).values():
                    if not isinstance(group, list):
                        raise ValueError("invalid dependency group")
                    specs.extend(group)
                locks = {str(parent / name) for name in ("uv.lock", "poetry.lock")}
                locks &= parsed.keys()
                if specs and not locks:
                    report.inventory_gap(f"Python project lacks a supported transitive lockfile: {path}")
                    continue
                for spec in specs:
                    requirement = python_requirement(spec)
                    if requirement is None:
                        report.inventory_gap(f"Unsupported Python dependency declaration: {path}")
                        continue
                    name, constraint = requirement
                    candidates = [d for d in dependencies if d.path in locks and d.name == name and d.ecosystem == "PyPI"]
                    if not candidates:
                        report.inventory_gap(f"Python dependency missing from lock entries: {path}")
                        continue
                    matches = [satisfies(d.version, constraint, "PyPI") for d in candidates]
                    if True not in matches:
                        report.inventory_gap(f"Python locked version conflicts or uses unsupported constraints: {path}")
            except (TypeError, AttributeError, ValueError):
                report.inventory_gap(f"Malformed Python dependency declarations: {path}")
