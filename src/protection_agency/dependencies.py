"""Parse inventories as data, without invoking package managers or build backends."""
import json
import re
import tomllib
from urllib.parse import urlsplit

from .intelligence import POLINRIDER_NPM, SOURCE
from .models import Dependency, Finding, Report

NPM_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*", re.I)
PY_NAME = re.compile(r"[a-z0-9][a-z0-9._-]*", re.I)
PY_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)(?:\s*;.*)?$")
PY_VERSION = re.compile(r"(?:\d+!)?\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?", re.I)
PRIVATE_NPM_HOSTS = {"registry.npmjs.org"}


def public_registry(url: str, ecosystem: str) -> bool:
    if not isinstance(url, str):
        return False
    try:
        parsed = urlsplit(url)
        hosts = PRIVATE_NPM_HOSTS if ecosystem == "npm" else {"pypi.org", "files.pythonhosted.org"}
        return (parsed.scheme == "https" and parsed.hostname in hosts and parsed.port in {None, 443}
                and parsed.username is None and parsed.password is None)
    except ValueError:
        return False


def python_pin(spec: str, path: str, report: Report, public: bool = True) -> Dependency | None:
    match = PY_PIN.fullmatch(spec.strip())
    if not match or len(match[2]) > 200 or not PY_VERSION.fullmatch(match[2]):
        report.inventory_gap(f"Python dependency not exactly pinned or unsupported syntax: {path}")
        return None
    if len(match[1]) > 214:
        report.inventory_gap(f"Unsupported Python package identity: {path}")
        return None
    name = re.sub(r"[-_.]+", "-", match[1]).lower()
    return Dependency("PyPI", name, match[2], path, public)


def parse_inventory(path: str, text: str, report: Report, npm_public: bool = True,
                    manifest_locked: bool = False) -> list[Dependency]:
    name = path.rsplit("/", 1)[-1]
    result = []
    try:
        if name in {"package-lock.json", "npm-shrinkwrap.json"}:
            data = json.loads(text)
            if data.get("lockfileVersion") not in {2, 3} or not isinstance(data.get("packages"), dict):
                report.inventory_gap(f"Unsupported npm lockfile (requires v2/v3): {path}")
                return []
            for location, item in data["packages"].items():
                if not location or "node_modules/" not in location:
                    continue
                if not isinstance(item, dict):
                    report.inventory_gap(f"Malformed npm lock entry: {path}")
                    continue
                if item.get("link"):
                    report.inventory_gap(f"Linked npm package not an advisory-checkable registry release: {path}")
                    continue
                package = item.get("name") or location.rsplit("node_modules/", 1)[-1]
                version = item.get("version", "")
                if (not isinstance(package, str) or len(package) > 214 or not NPM_NAME.fullmatch(package)
                        or not isinstance(version, str) or len(version) > 200 or not NPM_VERSION.fullmatch(version)):
                    report.inventory_gap(f"Unresolved npm release: {path}")
                    continue
                resolved = item.get("resolved", "")
                public = npm_public and isinstance(resolved, str) and public_registry(resolved, "npm")
                result.append(Dependency("npm", package, version, path, public))
                if item.get("hasInstallScript"):
                    report.findings.append(Finding("PA202", "medium", path, 1,
                        "Dependency declares an installation script",
                        "Inspect this package's lifecycle script before enabling scripts.",
                        package=package, version=version))
                if not item.get("integrity"):
                    report.findings.append(Finding("PA203", "medium", path, 1,
                        "Locked registry dependency lacks an integrity hash",
                        "Review package provenance and regenerate the lockfile in an isolated environment.",
                        package=package, version=version))
        elif name == "package.json":
            data = json.loads(text)
            scripts = data.get("scripts", {})
            if not isinstance(scripts, dict):
                raise ValueError("invalid scripts")
            for key in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
                if scripts.get(key):
                    report.findings.append(Finding("PA201", "medium", path, 1,
                        f"Package lifecycle script: {key}",
                        "Review the script and anything it executes; install with scripts disabled first."))
            # Direct exact pins supplement lockfiles and catch known bad versions even without one.
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                deps = data.get(section, {})
                if not isinstance(deps, dict):
                    raise ValueError("invalid dependencies")
                for package, version in deps.items():
                    if not NPM_NAME.fullmatch(package) or len(package) > 214 or not isinstance(version, str):
                        raise ValueError("invalid version")
                    if version.startswith("npm:"):
                        package, _, version = version[4:].rpartition("@")
                        if not NPM_NAME.fullmatch(package) or len(package) > 214:
                            raise ValueError("invalid alias")
                    if NPM_VERSION.fullmatch(version):
                        # A manifest cannot establish which registry resolves a name.
                        result.append(Dependency("npm", package, version, path, False))
        elif name in {"uv.lock", "poetry.lock"}:
            data = tomllib.loads(text)
            packages = data.get("package")
            if not isinstance(packages, list):
                raise ValueError("missing package list")
            for item in packages:
                source = item.get("source", {})
                if not isinstance(source, dict):
                    raise ValueError("invalid source")
                if name == "uv.lock" and ("virtual" in source or "editable" in source):
                    continue
                version = item.get("version")
                package = item.get("name")
                if (not isinstance(package, str) or len(package) > 214 or not PY_NAME.fullmatch(package)
                        or not isinstance(version, str)
                        or len(version) > 200 or not PY_VERSION.fullmatch(version)):
                    report.inventory_gap(f"Unresolved Python lock entry: {path}")
                    continue
                public = (public_registry(source.get("registry", ""), "PyPI") if name == "uv.lock"
                          else not source or public_registry(source.get("url", ""), "PyPI"))
                result.append(Dependency("PyPI", re.sub(r"[-_.]+", "-", package).lower(), version, path, public))
        elif name == "pyproject.toml":
            data = tomllib.loads(text)
            project = data.get("project", {})
            deps = project.get("dependencies", [])
            groups = project.get("optional-dependencies", {})
            if not isinstance(deps, list) or not isinstance(groups, dict):
                raise ValueError("invalid project dependencies")
            for group in groups.values():
                if not isinstance(group, list):
                    raise ValueError("invalid optional dependencies")
                deps = [*deps, *group]
            for spec in deps:
                if manifest_locked and isinstance(spec, str) and not PY_PIN.fullmatch(spec.strip()):
                    continue  # The lock coverage audit checks supported constraints.
                dep = python_pin(spec, path, report, False)
                if dep:
                    result.append(dep)
            dynamic = project.get("dynamic", [])
            if not isinstance(dynamic, list):
                raise ValueError("invalid dynamic metadata")
            if {"dependencies", "optional-dependencies"} & set(dynamic) or data.get("tool", {}).get("poetry"):
                report.inventory_gap(f"Dynamic or Poetry manifest dependencies require separate review: {path}")
        elif name.startswith("requirements") and name.endswith((".txt", ".in")):
            custom = bool(re.search(r"(?:--(?:extra-)?index-url|--find-links|(?:^|\n)-[if])\b", text))
            for raw in text.replace("\\\n", " ").splitlines():
                spec = re.split(r"\s+#", raw, maxsplit=1)[0].strip()
                if not spec or spec.startswith("#"):
                    continue
                if spec.startswith("-"):
                    report.inventory_gap(f"Requirements directives are not followed: {path}")
                    continue
                spec = re.sub(r"\s+--hash=\S+", "", spec)
                dep = python_pin(spec, path, report, not custom)
                if dep:
                    result.append(dep)
            report.inventory_gap(f"Requirements pins alone do not establish full transitive coverage: {path}")
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        report.inventory_gap(f"Malformed or unsupported inventory: {path}")
    for dep in result:
        if dep.ecosystem == "npm" and dep.version in POLINRIDER_NPM.get(dep.name, set()):
            report.findings.append(Finding("PA200", "critical", path, 1,
                "Published malicious PolinRider package release",
                "Do not install or import this release. If it ran, investigate the host and exposed credentials.",
                "published_malicious_version", SOURCE, dep.name, dep.version))
    return result
