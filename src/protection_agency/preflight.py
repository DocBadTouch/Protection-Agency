"""Inspect proposed releases as data. No resolver, package manager, or code runs."""
import re
import shlex
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import PurePosixPath

from .dependencies import NPM_VERSION, PY_VERSION, NPM_NAME, PY_NAME, public_registry
from .intelligence import POLINRIDER_NPM, SOURCE
from .models import Dependency, Finding, Report
from .osv import OSVClient

def check_dependency(ecosystem: str, name: str, version: str = "", *, registry=None,
                     online: bool = False, osv_client=None) -> dict:
    if ecosystem not in {"npm", "PyPI"} or not isinstance(name, str) or len(name) > 214:
        raise ValueError("invalid ecosystem or package name")
    pattern = NPM_NAME if ecosystem == "npm" else PY_NAME
    if not pattern.fullmatch(name) or not isinstance(version, str) or len(version) > 200:
        raise ValueError("invalid package identity")
    if registry is not None and (not isinstance(registry, str) or len(registry) > 2048):
        raise ValueError("invalid registry")
    name = name.lower() if ecosystem == "npm" else re.sub(r"[-_.]+", "-", name).lower()
    exact = bool(NPM_VERSION.fullmatch(version) if ecosystem == "npm"
                 else PY_VERSION.fullmatch(version))
    public = public_registry(registry, ecosystem)
    report = Report("quick", online)
    if not exact:
        report.inventory_gap("Proposed version is unresolved or unsupported; no registry resolution was attempted")
    if not public:
        report.gap("Registry provenance unspecified or private; package identity was not sent to OSV")
    if ecosystem == "npm" and version in POLINRIDER_NPM.get(name, set()):
        report.findings.append(Finding("PA200", "critical", "<proposed dependency>", 1,
            "Published malicious PolinRider package release",
            "Do not install or execute this release; confirm provenance when using a private registry.",
            "published_malicious_version", SOURCE, name, version, "proposed_dependency"))
    if online and exact and public:
        (osv_client or OSVClient()).check([Dependency(ecosystem, name, version, "<proposed dependency>")], report)
        if report.advisories == "complete":
            report.advisory_checked_at = datetime.now(timezone.utc).isoformat()
    return {"decision": report.decision,
            "target": {"ecosystem": ecosystem, "name": name, "version": version,
                       "registry": "public" if public else "unspecified_or_private"},
            "findings": [f.detail() for f in report.ordered()[:5]],
            "coverage": {"scope": "exact_release_only", "advisories": report.advisories,
                         "advisory_checked_at": report.advisory_checked_at,
                         "gaps": report.gaps, "transitive_dependencies": "not_checked",
                         "artifact_contents": "not_checked"}}


def check_dependencies(targets: list[dict], *, online: bool = False, osv_client=None) -> list[dict]:
    """Batch eligible proposed releases into one OSV check with one time budget."""
    results = [check_dependency(**target) for target in targets]
    if not online:
        return results
    eligible = {str(index): result for index, result in enumerate(results)
                if not result["coverage"]["gaps"] and result["decision"] != "block"}
    if not eligible:
        return results
    report = Report("quick", True)
    deps = [Dependency(r["target"]["ecosystem"], r["target"]["name"], r["target"]["version"], index)
            for index, r in eligible.items()]
    (osv_client or OSVClient()).check(deps, report)
    checked_at = datetime.now(timezone.utc).isoformat() if report.advisories == "complete" else None
    for index, result in eligible.items():
        findings = [replace(f, path="<proposed dependency>", context="proposed_dependency").detail()
                    for f in report.ordered() if f.path == index]
        result["findings"] = findings[:5]
        result["coverage"].update(advisories=report.advisories, advisory_checked_at=checked_at,
                                  gaps=list(report.gaps))
        result["decision"] = ("block" if any(f["severity"] in {"critical", "high"} for f in findings)
                              else "review" if findings or report.gaps or report.advisories != "complete"
                              else "no_findings")
    return results


def command_targets(command: str) -> list[dict]:
    """Recognize simple install invocations; unknown shell grammar stays review-only.

    This is a target extractor, not authorization and not a complete shell parser.
    It never evaluates expansions or follows requirement files.
    """
    if any(char in command for char in ";&|<>$`\n\r"):
        return []
    try:
        words = shlex.split(command)
    except ValueError:
        return []
    if not words:
        return []
    executable = PurePosixPath(words[0]).name
    args, ecosystem, single = words[1:], None, False
    if executable in {"npm", "pnpm", "yarn", "bun"} and args and args[0] in {"install", "i", "add"}:
        ecosystem, args = "npm", args[1:]
    elif executable in {"npx", "bunx"}:
        ecosystem, single = "npm", True
    elif re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", executable) and args[:3] == ["-m", "pip", "install"]:
        ecosystem, args = "PyPI", args[3:]
    elif re.fullmatch(r"pip(?:\d+(?:\.\d+)?)?", executable) and args[:1] == ["install"]:
        ecosystem, args = "PyPI", args[1:]
    elif executable == "uv" and args[:2] == ["pip", "install"]:
        ecosystem, args = "PyPI", args[2:]
    elif executable in {"uv", "poetry"} and args[:1] == ["add"]:
        ecosystem, args = "PyPI", args[1:]
    if ecosystem is None:
        return []
    specs, registry, uncertain_source, index = [], None, False, 0
    valued = {"--registry", "--index-url", "-i", "--extra-index-url", "--prefix", "--cache",
              "--workspace", "-w", "--target", "--platform", "--python-version", "--root",
              "--requirement", "-r", "--constraint", "-c", "--package", "-p"}
    switches = {"--yes", "-y", "--save", "--save-dev", "-D", "-S", "--save-exact", "-E",
                "--ignore-scripts", "--no-save", "--no-package-lock", "--legacy-peer-deps",
                "--force", "--prefer-offline", "--offline", "--dry-run", "--no-audit", "--no-fund", "--no-deps"}
    while index < len(args):
        word = args[index]
        option, equal, value = word.partition("=")
        if option in valued:
            if not equal:
                index += 1
                if index >= len(args):
                    break
                value = args[index]
            if option in {"--registry", "--index-url", "-i"}:
                registry = value
            elif option == "--extra-index-url":
                uncertain_source = True
            elif option in {"--package", "-p"}:
                specs.append(value)
        elif not word.startswith("-"):
            specs.append(word)
            if single:
                break  # Following words are arguments to the invoked program.
        elif word not in switches:
            uncertain_source = True  # Unknown option values may be private configuration.
        index += 1
    targets = []
    for spec in specs[:32]:
        if ecosystem == "npm":
            if spec.startswith("npm:"):
                spec = spec[4:]
            elif "@npm:" in spec:
                spec = spec.split("@npm:", 1)[1]
            name, separator, version = spec.rpartition("@")
            if not separator or not name:
                name, version = spec, ""
            if not NPM_NAME.fullmatch(name):
                continue
        else:
            match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?(?:==([^; ]+))?", spec)
            if not match:
                continue
            name, version = match[1], match[2] or ""
        if len(name) > 214 or len(version) > 200:
            continue
        targets.append({"ecosystem": ecosystem, "name": name, "version": version,
                        "registry": None if uncertain_source or (registry and len(registry) > 2048) else registry})
    return targets
