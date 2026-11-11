from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import uuid


def label(value: str, limit: int = 180) -> str:
    """Keep untrusted metadata bounded and remove terminal control characters."""
    return "".join(c for c in str(value) if c.isprintable())[:limit]


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    title: str
    action: str
    evidence: str = "heuristic"
    reference: str = ""
    package: str = ""
    version: str = ""

    @property
    def id(self) -> str:
        raw = repr(asdict(self)).encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def brief(self) -> dict:
        return {"id": self.id, "rule": self.rule, "severity": self.severity,
                "path": label(self.path), "line": self.line, "title": self.title}

    def detail(self) -> dict:
        data = {k: label(v, 700) if isinstance(v, str) else v
                for k, v in asdict(self).items() if v != ""}
        return {"id": self.id, **data}


@dataclass(frozen=True, order=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    path: str
    public: bool = True


@dataclass
class Report:
    level: str
    online: bool
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    files: int = 0
    bytes_read: int = 0
    dependencies: int = 0
    cached_files: int = 0
    advisories: str = "not_requested"
    advisory_checked_at: str | None = None

    def gap(self, message: str) -> None:
        message = label(message)
        if message not in self.gaps and len(self.gaps) < 40:
            self.gaps.append(message)

    @property
    def decision(self) -> str:
        if any(f.severity in {"critical", "high"} for f in self.findings):
            return "block"
        if self.gaps or self.findings or self.advisories != "complete":
            return "review"
        return "no_findings"

    def ordered(self) -> list[Finding]:
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted({f.id: f for f in self.findings}.values(),
                      key=lambda f: (rank[f.severity], f.path, f.line, f.rule))

    def summary(self, limit: int = 5) -> dict:
        findings = self.ordered()
        return {
            "report_id": self.id, "decision": self.decision,
            "level": self.level, "findings": len(findings),
            "top": [f.brief() for f in findings[:limit]],
            "coverage": {"files": self.files, "bytes": self.bytes_read,
                         "packages": self.dependencies, "advisories": self.advisories,
                         "source_scope": {"quick": "manifests_and_configuration", "standard": "project_text", "deep": "project_and_installed_text"}[self.level],
                         "advisory_checked_at": self.advisory_checked_at,
                         "gaps": self.gaps, "cached_files": self.cached_files},
            "more": max(0, len(findings) - limit),
        }

    def full(self) -> dict:
        return {**self.summary(), "created_at": self.created_at,
                "details": [f.detail() for f in self.ordered()]}
