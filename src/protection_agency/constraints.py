"""A deliberately limited stable-version check; unsupported syntax returns None.

This checks represented lock entries. It never resolves dependencies and does
not claim the full npm semver or Python PEP 440 language.
"""
import re

PY_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,. -]+\])?\s*(.*)$")


def python_requirement(spec: str) -> tuple[str, str] | None:
    if not isinstance(spec, str) or len(spec) > 4096:
        return None
    match = PY_REQUIREMENT.fullmatch(spec.split(";", 1)[0].strip())
    if not match or "@" in match[2]:
        return None
    return re.sub(r"[-_.]+", "-", match[1]).lower(), match[2].strip()


def satisfies(version: str, spec: str, ecosystem: str) -> bool | None:
    if not isinstance(spec, str) or not isinstance(version, str) or len(spec) > 4096:
        return None
    spec = spec.strip()
    if ecosystem == "npm" and "," in spec:
        return None
    if ecosystem == "npm" and spec.startswith("npm:"):
        spec = spec.rpartition("@")[2]
    # Exact strings can be checked even when ordering of prereleases is unknown.
    exact = spec.removeprefix("==").removeprefix("=").strip()
    if exact == version:
        return True
    if not re.fullmatch(r"\d+(?:\.\d+){0,3}", version):
        return None
    parts = tuple(int(p) for p in version.split("."))
    current = parts + (0,) * (4 - len(parts))
    if not spec or spec == "*":
        return True
    if ecosystem == "npm" and "||" in spec:
        results = [satisfies(version, branch, ecosystem) for branch in spec.split("||")]
        return True if True in results else None if None in results else False
    pattern = re.compile(r"(\^|~=|~|>=|<=|!=|==|>|<|=)?\s*(\d+(?:\.\d+){0,3})")
    position, results = 0, []
    for match in pattern.finditer(spec):
        separator = spec[position:match.start()]
        if separator.strip(" ,") or (results and not separator):
            return None
        op = match[1] or "=="
        bound_parts = tuple(int(p) for p in match[2].split("."))
        if ecosystem == "npm" and len(bound_parts) != 3:
            return None
        bound = bound_parts + (0,) * (4 - len(bound_parts))
        comparisons = {"==": current == bound, "=": current == bound,
                       "!=": current != bound, ">=": current >= bound,
                       "<=": current <= bound, ">": current > bound, "<": current < bound}
        if op in comparisons:
            results.append(comparisons[op])
        else:
            if op == "^" and ecosystem == "npm":
                index = next((i for i, value in enumerate(bound_parts) if value), 2)
            elif op == "~" and ecosystem == "npm":
                index = 1
            elif op == "~=" and ecosystem == "PyPI" and len(bound_parts) >= 2:
                index = len(bound_parts) - 2
            else:
                return None
            upper = list(bound)
            upper[index] += 1
            upper[index + 1:] = [0] * (3 - index)
            results.append(bound <= current < tuple(upper))
        position = match.end()
    if not results or spec[position:].strip():
        return None
    return all(results)
