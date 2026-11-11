"""Opt-in OSV requests. Only public package names and versions leave the process."""
import json
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .models import Dependency, Finding, Report

ENDPOINT = "https://api.osv.dev/v1/querybatch"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("OSV redirects are not accepted")


def request_osv(queries: list[dict], timeout: float) -> dict:
    request = Request(ENDPOINT, json.dumps({"queries": queries}).encode(),
                      {"Content-Type": "application/json", "User-Agent": "ProtectionAgency/0.1.0"})
    with build_opener(NoRedirect).open(request, timeout=timeout) as response:
        body = response.read(4 * 1024 * 1024 + 1)
        if len(body) > 4 * 1024 * 1024:
            raise ValueError("OSV response exceeds budget")
        return json.loads(body)


class OSVClient:
    def __init__(self, transport=request_osv, *, seconds: float = 25):
        self.transport = transport
        self.seconds = seconds

    def check(self, dependencies: list[Dependency], report: Report) -> None:
        start = time.monotonic()
        packages = {}
        complete = True
        for dep in dependencies:
            if not dep.public:
                complete = False
                report.gap("Private, local, or unknown package sources omitted from OSV requests")
                continue
            packages.setdefault((dep.ecosystem, dep.name, dep.version), []).append(dep)
        keys = list(packages)
        try:
            for offset in range(0, len(keys), 100):
                active = [(key, {"package": {"ecosystem": key[0], "name": key[1]}, "version": key[2]})
                          for key in keys[offset:offset + 100]]
                pages = 0
                while active:
                    remaining = self.seconds - (time.monotonic() - start)
                    if remaining <= 0 or pages >= 10:
                        raise ValueError("OSV time or pagination budget exceeded")
                    payload = self.transport([q for _, q in active], min(8, remaining))
                    results = payload.get("results")
                    if not isinstance(results, list) or len(results) != len(active):
                        raise ValueError("OSV returned mismatched results")
                    followups = []
                    for (key, query), result in zip(active, results):
                        if not isinstance(result, dict) or result.get("error"):
                            raise ValueError("OSV query error")
                        vulns = result.get("vulns", [])
                        if not isinstance(vulns, list):
                            raise ValueError("invalid advisory list")
                        for vuln in vulns:
                            identifier = vuln.get("id") if isinstance(vuln, dict) else None
                            if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", identifier):
                                raise ValueError("invalid advisory identifier")
                            malicious = identifier.startswith("MAL-")
                            for dep in packages[key]:
                                report.findings.append(Finding(
                                    "PA300" if malicious else "PA301",
                                    "critical" if malicious else "medium", dep.path, 1,
                                    "Known malicious package advisory" if malicious else "Known vulnerability advisory",
                                    "Do not execute this release; investigate any prior execution." if malicious else
                                    "Review the advisory and affected usage; select a fixed version and rescan.",
                                    "osv_version_match", "https://osv.dev/vulnerability/" + quote(identifier, safe=""),
                                    dep.name, dep.version))
                        token = result.get("next_page_token")
                        if token:
                            if not isinstance(token, str) or len(token) > 8192:
                                raise ValueError("invalid OSV pagination token")
                            followups.append((key, {**query, "page_token": token}))
                    active = followups
                    pages += 1
        except (ValueError, TypeError, AttributeError, OSError, URLError, HTTPError, RecursionError):
            complete = False
            report.gap("OSV check failed, timed out, or returned incomplete data; no clean result asserted")
        report.advisories = "complete" if complete else "incomplete"
