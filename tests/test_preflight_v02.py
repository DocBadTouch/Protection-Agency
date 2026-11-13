"""Prevention regressions use inert metadata and an offline OSV transport."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from protection_agency.hooks import handle
from protection_agency.osv import OSVClient
from protection_agency.scanner import Scanner
from protection_agency.constraints import satisfies
from protection_agency.preflight import check_dependency, check_dependencies, command_targets
from protection_agency.policy import check_command
from protection_agency.mcp import Server
from protection_agency import jsondata

PROJECT = Path(__file__).resolve().parents[1]


class PreventionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content if isinstance(content, str) else json.dumps(content))
        return target

    def scan(self, level="standard"):
        client = OSVClient(lambda queries, timeout: {"results": [{} for _ in queries]})
        return Scanner(self.root, online=True, osv_client=client).scan(level)

    def package(self, version="1.2.3", **extra):
        return {"version": version, "resolved": "https://registry.npmjs.org/demo/-/demo.tgz",
                "integrity": "sha512-inert-fixture", **extra}

    def test_manifest_dependency_missing_from_lock_is_incomplete(self):
        self.write("package.json", {"dependencies": {"demo": "^1.0.0"}})
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {"": {}}})
        report = self.scan()
        self.assertEqual(report.decision, "review")
        self.assertTrue(report.gaps)
        self.assertEqual(report.summary()["coverage"]["inventory"], "incomplete")

    def test_missing_transitive_entry_is_incomplete(self):
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/demo": self.package(dependencies={"missing": "^1.0.0"})}})
        self.assertTrue(self.scan().gaps)

    def test_stale_root_declaration_is_incomplete(self):
        self.write("package.json", {"dependencies": {"demo": "^2.0.0"}})
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"demo": "^1.0.0"}}, "node_modules/demo": self.package()}})
        self.assertTrue(self.scan().gaps)

    def test_known_malicious_proposed_install_is_denied(self):
        result = handle({"hook_event_name": "PreToolUse", "cwd": str(self.root),
                         "tool_name": "Bash", "tool_input": {"command": "npm install cdeops@13.5.31"}})
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("malicious", result["hookSpecificOutput"]["permissionDecisionReason"].lower())

    def test_documentation_example_remains_visible_without_blocking(self):
        self.write("README.md", "An inert example: eval(atob('example'));\n")
        report = self.scan()
        self.assertEqual(report.decision, "review")
        self.assertEqual(report.findings[0].severity, "low")
        self.assertEqual(report.findings[0].context, "documentation")

    def test_project_startup_hook_is_reviewed_without_executing(self):
        self.write(".claude/settings.json", {"hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "node .vscode/setup.mjs"}]}]}})
        report = self.scan()
        self.assertIn("PA400", {f.rule for f in report.findings})
        self.assertEqual(report.decision, "review")

    def test_python_startup_files_are_selected(self):
        self.write("startup.pth", "import inert_example\n")
        report = self.scan()
        self.assertEqual(report.files, 1)
        self.assertIn("PA403", {f.rule for f in report.findings})

    def test_supported_uv_lock_covers_common_manifest_range(self):
        self.write("pyproject.toml", '[project]\nname="example"\nversion="0.1.0"\ndependencies=["requests>=2.0"]\n')
        self.write("uv.lock", 'version=1\n[[package]]\nname="requests"\nversion="2.32.0"\nsource={registry="https://pypi.org/simple"}\n')
        report = self.scan()
        self.assertEqual(report.dependencies, 1)
        self.assertFalse(report.gaps)

    def test_consistent_npm_lock_is_complete(self):
        declarations = {"dependencies": {"demo": "^1.0.0"}}
        self.write("package.json", declarations)
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": declarations, "node_modules/demo": self.package()}})
        report = self.scan()
        self.assertEqual(report.decision, "no_findings")
        self.assertTrue(report.summary()["coverage"]["complete"])
        self.assertEqual(report.inventory, "complete")

    def test_incompatible_resolved_version_is_incomplete(self):
        declarations = {"dependencies": {"demo": "^2.0.0"}}
        self.write("package.json", declarations)
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": declarations, "node_modules/demo": self.package("1.2.3")}})
        self.assertEqual(self.scan().inventory, "incomplete")

    def test_workspace_must_have_its_own_lock_representation(self):
        self.write("packages/app/package.json", {"dependencies": {"demo": "^1.0.0"}})
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/demo": self.package()}})
        self.assertEqual(self.scan().inventory, "incomplete")

    def test_workspace_with_matching_record_and_hoisted_dependency(self):
        declarations = {"dependencies": {"demo": "^1.0.0"}}
        self.write("packages/app/package.json", declarations)
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {}, "packages/app": declarations, "node_modules/demo": self.package()}})
        self.assertFalse(self.scan().gaps)

    def test_nested_dependency_is_resolved_from_closest_entry(self):
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/demo": self.package(dependencies={"child": "^2.0.0"}),
            "node_modules/child": self.package("1.0.0"),
            "node_modules/demo/node_modules/child": self.package("2.1.0")}})
        self.assertFalse(self.scan().gaps)

    def test_unsupported_constraint_remains_incomplete(self):
        declarations = {"dependencies": {"demo": "github:example/demo"}}
        self.write("package.json", declarations)
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": declarations, "node_modules/demo": self.package()}})
        self.assertEqual(self.scan().inventory, "incomplete")

    def test_unreadable_inventory_is_incomplete(self):
        (self.root / "package-lock.json").symlink_to("missing-lock.json")
        self.assertEqual(self.scan().inventory, "incomplete")

    def test_python_missing_or_incompatible_dependency_is_incomplete(self):
        self.write("pyproject.toml", '[project]\ndependencies=["demo>=2.0"]')
        for package in ("other", "demo"):
            self.write("uv.lock", f'version=1\n[[package]]\nname="{package}"\nversion="1.0"\nsource={{registry="https://pypi.org/simple"}}')
            self.assertEqual(self.scan().inventory, "incomplete")

    def test_malformed_python_dependency_shapes_remain_incomplete(self):
        for content in ('[project]\ndependencies=""', '[project.optional-dependencies]\ntest=""'):
            self.write("pyproject.toml", content)
            self.assertEqual(self.scan().inventory, "incomplete")

    def test_invalid_locked_package_identity_is_not_queried(self):
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/demo": self.package(name="../private")}})
        client = OSVClient(lambda *_: self.fail("invalid package identity reached OSV"))
        report = Scanner(self.root, online=True, osv_client=client).scan()
        self.assertEqual(report.inventory, "incomplete")
        self.assertFalse(report.summary()["coverage"]["complete"])

    def test_documentation_downgrade_does_not_hide_agent_instructions(self):
        for path in ("AGENTS.md", "CLAUDE.md", "SKILL.md", ".claude/rules/security.md"):
            self.write(path, "eval(atob('inert-example'))")
        self.assertEqual(self.scan().decision, "block")

    def test_startup_jsonc_and_mcp_commands_are_inspected_without_running(self):
        self.write(".vscode/tasks.json", '''{
          // Inert task; never executed
          "tasks": [{"runOptions":{"runOn":"folderOpen",},"command":"touch EXECUTED",}],
        }''')
        self.write(".mcp.json", {"mcpServers": {"inert": {"command": "touch", "args": ["EXECUTED"]}}})
        self.write("binding.gyp", "{}")
        report = self.scan("quick")
        self.assertTrue({"PA109", "PA402", "PA405"} <= {f.rule for f in report.findings})
        self.assertFalse((self.root / "EXECUTED").exists())
        cached = Scanner(self.root)
        first, second = cached.scan("quick"), cached.scan("standard")
        self.assertEqual({f.id for f in first.findings}, {f.id for f in second.findings})

    def test_malformed_or_over_budget_hook_config_reports_gap(self):
        for data in ({"hooks": "unknown"}, {"hooks": {"SessionStart": "unknown"}},
                     {"hooks": {"SessionStart": [{"hooks": [{"type": "unknown"}]}]}}):
            self.write(".claude/settings.json", data)
            self.assertTrue(self.scan().gaps)
        nested = {}
        for _ in range(14):
            nested = {"hooks": [nested]}
        self.write(".claude/settings.json", {"hooks": {"SessionStart": [nested]}})
        self.assertTrue(self.scan().gaps)

    def test_cached_startup_parse_errors_are_not_lost(self):
        self.write(".claude/settings.json", "invalid JSON")
        scanner = Scanner(self.root)
        self.assertTrue(scanner.scan().gaps)
        self.assertTrue(scanner.scan().gaps)


class ProposedDependencyTests(unittest.TestCase):
    def test_exact_known_malicious_commands_are_denied_offline(self):
        for command in ("npm install cdeops@13.5.31", "npm i alias@npm:cdeops@13.5.31",
                        "pnpm add cdeops@13.5.31", "yarn add cdeops@13.5.31",
                        "bun add cdeops@13.5.31", "npx --yes cdeops@13.5.31",
                        "npx --package=cdeops@13.5.31 inert-command"):
            self.assertEqual(check_command(command)["decision"], "deny", command)

    def test_python_and_scoped_package_targets(self):
        targets = command_targets("python3 -m pip install 'Requests[socks]==2.32.0'")
        self.assertEqual(targets[0]["ecosystem"], "PyPI")
        self.assertEqual(targets[0]["version"], "2.32.0")
        targets = command_targets("npm install @scope/example@1.2.3")
        self.assertEqual(targets[0]["name"], "@scope/example")
        self.assertEqual(command_targets("npx example@1.0.0 cdeops@13.5.31")[0]["name"], "example")
        self.assertEqual(len(command_targets("npx example@1.0.0 cdeops@13.5.31")), 1)

    def test_private_and_unknown_sources_never_query_osv(self):
        client = OSVClient(lambda *_: self.fail("unexpected external query"))
        for registry in (None, "https://private.example/simple", "https://user:secret@pypi.org/simple", "https://pypi.org:8080/simple"):
            result = check_dependency("PyPI", "private", "1.0", registry=registry, online=True, osv_client=client)
            self.assertEqual(result["decision"], "review")
            self.assertEqual(result["coverage"]["advisories"], "not_requested")
            self.assertNotIn("secret", json.dumps(result))

    def test_unresolved_versions_never_query_osv(self):
        client = OSVClient(lambda *_: self.fail("resolver must not run"))
        for ecosystem, versions, registry in (("npm", ["", "latest", "^1.0.0"], "https://registry.npmjs.org"),
                                             ("PyPI", ["", ">=1.0", "1+_"], "https://pypi.org/simple")):
            for version in versions:
                result = check_dependency(ecosystem, "example", version, registry=registry, online=True, osv_client=client)
                self.assertEqual(result["decision"], "review")
                self.assertTrue(result["coverage"]["gaps"])

    def test_public_exact_target_checks_osv_and_discloses_scope(self):
        queries_seen = []
        def transport(queries, timeout):
            queries_seen.extend(queries)
            return {"results": [{"vulns": [{"id": "MAL-2026-INERT"}]}]}
        result = check_dependency("PyPI", "Demo_Pkg", "1.0", registry="https://pypi.org/simple",
                                  online=True, osv_client=OSVClient(transport))
        self.assertEqual(result["decision"], "block")
        self.assertEqual(queries_seen[0]["package"]["name"], "demo-pkg")
        self.assertEqual(result["coverage"]["transitive_dependencies"], "not_checked")
        self.assertNotIn("path", queries_seen[0])

    def test_public_zero_match_is_limited_to_exact_release(self):
        client = OSVClient(lambda *_: {"results": [{}]})
        result = check_dependency("npm", "example", "1.0.0", registry="https://registry.npmjs.org", online=True, osv_client=client)
        self.assertEqual(result["decision"], "no_findings")
        self.assertEqual(result["coverage"]["scope"], "exact_release_only")
        self.assertEqual(result["coverage"]["artifact_contents"], "not_checked")

    def test_offline_mcp_cannot_enable_networking_per_tool_call(self):
        with tempfile.TemporaryDirectory() as directory:
            server = Server(Scanner(Path(directory)))
            with self.assertRaises(ValueError):
                server.call("check_dependency", {"ecosystem": "npm", "name": "example", "online": True})
            result = server.call("check_dependency", {"ecosystem": "npm", "name": "cdeops", "version": "13.5.31"})
            self.assertEqual(result["decision"], "block")

    def test_unknown_shell_wrappers_still_require_review(self):
        for command in ("env npm install example@1.0.0", "npm install $(dynamic)", "cd other && npm install example", "bash -c 'npm install example'"):
            self.assertEqual(check_command(command)["decision"], "ask")
            self.assertEqual(command_targets(command), [])

    def test_target_parser_and_registry_metadata_are_bounded(self):
        command = "npm install " + " ".join(f"example{i}@1.0.0" for i in range(100))
        self.assertLessEqual(len(command_targets(command)), 32)
        self.assertEqual(check_command("npm install " + "a" * 220 + "@1.0.0")["decision"], "ask")
        with self.assertRaises(ValueError):
            check_dependency("npm", "../../outside", "1.0.0")

    def test_unknown_options_and_extra_indexes_suppress_target_queries(self):
        for command in ("npm install --registry=https://registry.npmjs.org --userconfig private@1.0.0 example@1.0.0",
                        "pip install --index-url https://pypi.org/simple --extra-index-url https://private.example/simple example==1.0"):
            targets = command_targets(command)
            self.assertTrue(targets)
            self.assertTrue(all(t["registry"] is None for t in targets))

    def test_hook_surfaces_target_advisory_failure(self):
        result = {"decision": "review", "coverage": {"advisories": "incomplete"}}
        with tempfile.TemporaryDirectory() as directory, patch("protection_agency.hooks.check_dependencies", return_value=[result]):
            output = handle({"hook_event_name": "PreToolUse", "cwd": directory,
                             "tool_name": "Bash", "tool_input": {"command": "npm install example@1.0.0"}})
            specific = output["hookSpecificOutput"]
            self.assertEqual(specific["permissionDecision"], "ask")
            self.assertIn("Proposed-release advisories incomplete", specific["permissionDecisionReason"])

    def test_multiple_proposed_releases_share_one_osv_request(self):
        calls = []
        def transport(queries, timeout):
            calls.append(queries)
            return {"results": [{}, {"vulns": [{"id": "MAL-2026-INERT"}]}]}
        targets = command_targets("npm install --registry=https://registry.npmjs.org one@1.0.0 two@2.0.0")
        results = check_dependencies(targets, online=True, osv_client=OSVClient(transport))
        self.assertEqual(len(calls), 1)
        self.assertEqual([r["decision"] for r in results], ["no_findings", "block"])
        self.assertTrue(all(r["coverage"]["advisory_checked_at"] for r in results))

    def test_real_mcp_dependency_tool_call(self):
        with tempfile.TemporaryDirectory() as directory:
            messages = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                    "name": "check_dependency", "arguments": {"ecosystem": "npm", "name": "cdeops", "version": "13.5.31"}}},
            ]
            process = subprocess.run([sys.executable, "-I", str(PROJECT / "guard.py"), "serve", "--root", directory],
                input="\n".join(json.dumps(m) for m in messages) + "\n", text=True, capture_output=True, timeout=5)
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout.splitlines()[1])["result"]
            self.assertFalse(result["isError"])
            self.assertEqual(json.loads(result["content"][0]["text"])["decision"], "block")


class DataAndDiagnosticsTests(unittest.TestCase):
    def test_json_comments_preserve_strings_and_comma_literals(self):
        data = jsondata.loads('{"url":"https://example.invalid//path", /* inert */ "value":"data,}",}')
        self.assertEqual(data["url"], "https://example.invalid//path")
        self.assertEqual(data["value"], "data,}")
        with self.assertRaises(ValueError):
            jsondata.loads('{"a":1, /* incomplete')

    def test_supported_constraints_and_unknown_syntax(self):
        for version, spec, ecosystem, expected in (
            ("1.9.0", "^1.2.3", "npm", True), ("2.0.0", "^1.2.3", "npm", False),
            ("0.0.2", "^0.0.1", "npm", False), ("1.3.0", "~1.2.3", "npm", False),
            ("2.0.0", "^1.0.0 || ^2.0.0", "npm", True),
            ("1.4.9", "~=1.4.5", "PyPI", True), ("1.5", "~=1.4.5", "PyPI", False),
            ("2.3", ">=2.0, <3.0, !=2.2", "PyPI", True),
            ("2.2", ">=2.0, <3.0, !=2.2", "PyPI", False),
            ("1.0.0", "github:example/repo", "npm", None),
            ("1.0.0", ">=1.0.0,<2.0.0", "npm", None),
            ("1.0rc1", ">=1.0", "PyPI", None)):
            self.assertIs(satisfies(version, spec, ecosystem), expected, (version, spec))

    def test_cli_dependency_check_and_doctor(self):
        dependency = subprocess.run([sys.executable, "-I", str(PROJECT / "guard.py"), "check-dependency", "npm", "cdeops", "13.5.31"], capture_output=True, text=True, timeout=5)
        self.assertEqual(dependency.returncode, 1)
        self.assertEqual(json.loads(dependency.stdout)["decision"], "block")
        doctor = subprocess.run([sys.executable, "-I", str(PROJECT / "guard.py"), "doctor"], capture_output=True, text=True, timeout=5)
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        result = json.loads(doctor.stdout)
        self.assertEqual(result["status"], "self_checks_passed")
        self.assertEqual(result["live_client_enforcement"], "not_verified")

    def test_doctor_does_not_contact_external_services(self):
        from protection_agency.doctor import diagnose
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("unexpected network")):
            self.assertEqual(diagnose()["status"], "self_checks_passed")
