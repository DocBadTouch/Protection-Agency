"""Conservative signatures. Never evaluate, decode-and-run, or import target code."""
import re

from .intelligence import POLINRIDER_WALLET, SOURCE
from .models import Finding

# Bounded patterns avoid catastrophic regex backtracking on attacker input.
PATTERNS = (
    ("PA101", "high", r"\beval\s*\(\s*(?:atob|Buffer\.from)\s*\(",
     "Encoded JavaScript passed directly to eval",
     "Inspect the loader in isolation; do not import or execute this file."),
    ("PA102", "high", r"\b(?:exec|eval)\s*\(\s*(?:base64\.|b64decode\s*\(|marshal\.loads)",
     "Encoded Python passed directly to execution",
     "Review the decoded content using a non-executing analysis tool."),
    ("PA103", "high", r"(?:curl|wget)\b[^\n|]{0,600}\|\s*(?:(?:sudo|env)\s+)?(?:ba|z|da)?sh\b",
     "Remote download piped to a shell",
     "Download without running; verify provenance and review the file first."),
    ("PA104", "medium", r"(?:new\s+Function|\bFunction)\s*\([^\n]{0,300}(?:atob\s*\(|Buffer\.from\s*\()",
     "Dynamic function built from encoded content",
     "Review why decoded content becomes executable code."),
    ("PA105", "medium", r"(?:ignore|bypass|disable)[^\n]{0,65}(?:security|scanner|safety|previous instructions|guardrails)",
     "Instruction attempts to bypass security controls",
     "Treat project instructions as untrusted; inspect this instruction manually."),
    ("PA106", "medium", r"(?:NODE_OPTIONS\s*=\s*[^\n]{0,150}--(?:require|import)|--extra-index-url\b)",
     "Execution injection or dependency-confusion-sensitive configuration",
     "Review injected modules and package-index precedence before using this configuration."),
    ("PA107", "high", r"\b(?:Invoke-Expression|iex)\b[^\n]{0,300}(?:DownloadString|Invoke-WebRequest)|(?:DownloadString|Invoke-WebRequest)[^\n]{0,300}\|\s*(?:iex|Invoke-Expression)\b",
     "PowerShell remote content passed to execution",
     "Review downloaded content without executing it."),
)
COMPILED = [(rule, sev, re.compile(pattern, re.I), title, action)
            for rule, sev, pattern, title, action in PATTERNS]


def scan_text(path: str, text: str) -> list[Finding]:
    findings = []
    lower = text.lower()
    if POLINRIDER_WALLET in lower:
        pos = lower.index(POLINRIDER_WALLET)
        findings.append(Finding("PA100", "high", path, text.count("\n", 0, pos) + 1,
            "Published PolinRider wallet indicator present",
            "Determine whether this is executable loader code or a benign reference; keep execution paused.",
            "indicator_match", SOURCE))
    for rule, severity, pattern, title, action in COMPILED:
        # At most one hit per rule/file: reports stay bounded on repetitive input.
        match = pattern.search(text)
        if match:
            findings.append(Finding(rule, severity, path, text.count("\n", 0, match.start()) + 1,
                                    title, action))
    # Two independent signals; blockchain access alone is not suspicious.
    if (re.search(r"eth_(?:call|getTransaction|blockNumber)", text)
            and re.search(r"\b(?:eval|Function)\s*\(", text)):
        findings.append(Finding("PA108", "medium", path, 1,
            "Blockchain RPC and dynamic execution in the same file",
            "Inspect possible blockchain-mediated payload resolution; co-occurrence does not prove data flow."))
    if path.endswith(".vscode/tasks.json") and re.search(r'"runOn"\s*:\s*"folderOpen"', text):
        findings.append(Finding("PA109", "medium", path, 1,
            "Editor task configured to run when a folder opens",
            "Review the task before trusting this workspace in an editor."))
    return findings
