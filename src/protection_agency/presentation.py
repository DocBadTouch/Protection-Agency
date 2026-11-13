"""Plain terminal summaries; no source excerpts, color escapes, or model calls."""
from .models import label

ADVISORIES = {
    "complete": "Current advisory lookup completed for eligible public dependency identities.",
    "not_requested": "Current vulnerability advisories were not checked (offline mode).",
}


def scan_result(report, *, full=False):
    lines = ["Protection Agency", {
        "block": "STOP: inspect these findings before running project code.",
        "review": "REVIEW NEEDED: findings or missing checks need attention.",
        "no_findings": "No known matches in the checked scope.",
    }[report.decision],
        f"Checked {report.files} selected files; identified {report.dependencies} dependency releases.",
        "Dependency inventory: " + {"complete": "supported inventory checks completed.",
            "incomplete": "incomplete; inspect missing checks.",
            "not_present": "no supported dependency inventory was identified."}[report.inventory],
        ADVISORIES.get(report.advisories, "Advisory coverage is incomplete; a current result could not be established.")]
    findings = report.ordered()
    for finding in (findings if full else findings[:5]):
        detail = finding.detail()
        lines.extend(["", f"[{detail['severity'].upper()}] {detail['title']}",
                      f"  Where: {detail['path']}:{detail['line']}"])
        if finding.package:
            lines.append("  Dependency: " + label(finding.package + "@" + finding.version))
        if finding.evidence == "heuristic":
            lines.append("  Evidence: pattern match; legitimate code can also match.")
        elif finding.evidence == "osv_version_match":
            lines.append("  Evidence: published advisory for this version; reachability is not established.")
        lines.append("  Next: " + detail["action"])
        if detail.get("reference"):
            lines.append("  Reference: " + detail["reference"])
    if not findings:
        lines.append("No local findings were reported.")
    if not full and len(findings) > 5:
        lines.append(f"{len(findings) - 5} more findings; repeat check with --full to read them.")
    if report.gaps:
        lines.append("\nChecks that could not be completed:")
        lines.extend("  - " + label(gap) for gap in (report.gaps if full else report.gaps[:5]))
        if not full and len(report.gaps) > 5:
            lines.append("  More gaps are available with --full or --json.")
    if report.advisories == "not_requested":
        lines.append("Next: add --online to check eligible public dependency identities with OSV; keep confidential inventories offline.")
    if report.decision == "no_findings":
        lines.append("This is a screening result, not a guarantee. Keep sandboxing and native permissions enabled.")
    lines.append("No project commands were executed by this check.")
    return "\n".join(lines)


def setup_result(result):
    messages = {
        "installed": "Claude user hooks installed.", "uninstalled": "Protection Agency hooks removed.",
        "already_installed": "The requested hooks are already configured.",
        "not_installed": "No matching Protection Agency hooks were found; settings were not changed.",
        "would_install": "Preview: add or replace the two Protection Agency hook groups.",
        "would_uninstall": "Preview: remove Protection Agency hook handlers only.",
        "disabled": "Setup stopped: user settings explicitly disable hooks.",
        "disabled_by_project": "Setup stopped: project settings explicitly disable hooks.",
        "conflict": "Setup stopped: settings changed or another setup holds the lock. Inspect current settings and retry.",
        "applied_with_warning": "Settings were changed, but their directory could not be synced. Inspect the resulting file.",
    }
    lines = [messages.get(result["status"], "Setup did not establish a completed result.")]
    if result.get("backup"):
        lines.append("Private original-byte backup: " + label(result["backup"]))
    if result.get("changed"):
        lines.append("Unrelated settings were preserved. Restart Claude after configuration changes.")
    lines.append("Native Claude enforcement: not verified.")
    return "\n".join(lines)


def doctor_result(result):
    passed = sum(c["status"] == "passed" for c in result["checks"])
    lines = [f"Local checks: {passed}/{len(result['checks'])} passed."]
    for check in result["checks"]:
        if check["status"] != "passed":
            lines.append("  Failed: " + label(check["check"]).replace("_", " "))
    integration = result.get("integration")
    if integration:
        lines.extend(["Hook configuration: " + label(integration["status"]),
                      "Trusted hook response test: " + label(integration["probe"]),
                      "Required Claude version: " + integration["minimum_client_version"] + "+ (installed version not checked)."])
    lines.extend(label(warning) for warning in result.get("warnings", []))
    lines.append("Native Claude enforcement: not verified. Confirm this profile and its hooks in the actual client.")
    return "\n".join(lines)


def launch_receipt(data):
    """Format trusted launch receipts without changing the gate or review challenge."""
    if "review_findings" in data:
        lines = ["Review these findings before answering the terminal challenge:"]
        for finding in data["review_findings"]:
            lines.extend([f"[{label(finding['severity']).upper()}] {label(finding['title'], 700)}",
                          f"  Where: {label(finding['path'], 700)}:{finding['line']}",
                          "  Next: " + label(finding["action"], 700)])
            for key, value in finding.items():
                if key not in {"severity", "title", "path", "line", "action"}:
                    lines.append("  " + key.replace("_", " ") + ": " + label(str(value), 700))
        return "\n".join(lines)
    if "report" in data:
        report = data["report"]
        lines = ["Protection Agency startup check: " + report["decision"].replace("_", " "),
                 f"{report['findings']} findings; advisory coverage: {report['coverage']['advisories']}.",
                 "Scope: selected project text and Git startup metadata; installed sources and trusted global settings are excluded."]
        for finding in report["top"]:
            lines.append(f"  [{label(finding['severity']).upper()}] {label(finding['title'])} ({label(finding['path'])}:{finding['line']})")
        lines.extend("  Missing check: " + label(g) for g in report["coverage"]["gaps"][:5])
        if report["decision"] == "block":
            lines.append("Client not started. Run check --online --full for evidence and next steps.")
        elif (report["coverage"]["gaps"] or report["coverage"]["advisories"] != "complete"
              or report["coverage"].get("inventory") == "incomplete"):
            lines.append("Client not started: requested checks are incomplete. Review gaps; online advisory coverage is required.")
        elif report["decision"] == "review":
            lines.append("Findings need review before launch. Use check --online --full; --review permits a limited terminal review when coverage is complete.")
        return "\n".join(lines)
    if data.get("execution") == "starting":
        return "Starting the selected client. Keep its sandbox and native permissions enabled; this launcher provides no sandbox."
    return label(data.get("reason", "Client was not started."), 700)
