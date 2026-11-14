"""Shared adapter tests. No native model session or target command runs."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from protection_agency.agents import capabilities, default_settings
from protection_agency.hooks import handle
from protection_agency.integration import configure, inspect_configuration
from protection_agency.onboarding import setup, open_client
from protection_agency.startup import inspect

SOURCE = Path(__file__).resolve().parents[1]


class AgentsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pa-agents-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        self.settings = self.base / "user/hooks.json"

    def event(self, command):
        return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(self.project),
                "tool_input": {"command": command}}

    def cli(self, *args, input=None):
        return subprocess.run([sys.executable, "-I", str(SOURCE / "guard.py"), *map(str, args)],
                              input=input, capture_output=True, text=True, cwd=self.project, timeout=20)

    def test_capabilities_distinguish_review_and_failure_behaviors(self):
        adapters = {a["name"]: a for a in capabilities()["agents"]}
        self.assertEqual(set(adapters), {"codex", "claude"})
        self.assertFalse(adapters["codex"]["native_review_supported"])
        self.assertTrue(adapters["claude"]["native_review_supported"])
        self.assertEqual(adapters["codex"]["hook_error_behavior"], "may_continue_on_error_or_timeout")
        self.assertTrue(all(a["native_enforcement"] == "not_verified" for a in adapters.values()))

    def test_agent_cli_reports_shared_mcp_without_claiming_enforcement(self):
        result = self.cli("agents", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["agents"]), 2)

    def test_profiles_are_agent_specific_and_respect_explicit_selection(self):
        with patch.dict(os.environ, {"CODEX_HOME": str(self.base / "codex"), "CLAUDE_CONFIG_DIR": str(self.base / "claude")}):
            self.assertEqual(default_settings("codex"), self.base / "codex/hooks.json")
            self.assertEqual(default_settings("claude"), self.base / "claude/settings.json")
            self.assertEqual(default_settings("codex", self.settings), self.settings)

    def test_codex_denies_known_malicious_release_and_never_returns_ask(self):
        output = handle(self.event("npm install cdeops@13.5.31"), agent="codex")
        self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")
        review = handle(self.event("npm test"), agent="codex")
        self.assertEqual(review["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("cannot request", review["hookSpecificOutput"]["permissionDecisionReason"])

    def test_simple_reads_keep_native_permissions_for_both_adapters(self):
        for agent in ("codex", "claude"):
            self.assertEqual(handle(self.event("pwd"), agent=agent), {})

    def test_windows_package_shim_names_preserve_malicious_target_detection(self):
        for command in ('npm.cmd install cdeops@13.5.31', 'npm.exe install cdeops@13.5.31',
                        '"C:\\Program Files\\nodejs\\npm.cmd" install cdeops@13.5.31'):
            result = handle(self.event(command), agent="codex")
            self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
            self.assertIn("malicious", result["hookSpecificOutput"]["permissionDecisionReason"].lower())

    def test_codex_malformed_input_is_explicit_json_denial_with_exit_zero(self):
        result = self.cli("hook", "--agent", "codex", input="{inert-private-bad-input")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertNotIn("inert-private-bad-input", result.stdout + result.stderr)

    def test_claude_malformed_input_keeps_original_exit_two_contract(self):
        self.assertEqual(self.cli("hook", "--agent", "claude", input="{}").returncode, 2)

    def test_codex_install_and_probe_use_its_canonical_schema(self):
        result = configure("install", self.settings, self.project, agent="codex", online=True)
        self.assertEqual(result["status"], "installed")
        data = json.loads(self.settings.read_text(encoding="utf-8"))
        handler = data["hooks"]["PreToolUse"][0]["hooks"][0]
        self.assertNotIn("onFailure", handler)
        self.assertNotIn("args", handler)
        self.assertIn("codex", handler["command"] if os.name != "nt" else result["client"])
        inspection = inspect_configuration(self.settings, self.project, agent="codex", probe=True)
        self.assertEqual(inspection["status"], "configured")
        self.assertEqual(inspection["probe"], "passed")
        self.assertEqual(inspection["live_client_enforcement"], "not_verified")

    def test_codex_install_preserves_unrelated_hooks_and_uninstall_later_edits(self):
        self.settings.parent.mkdir()
        self.settings.write_text('{"description":"private settings","hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo inert"}]}]}}')
        configure("install", self.settings, self.project, agent="codex")
        data = json.loads(self.settings.read_text())
        data["new_user_value"] = 42
        self.settings.write_text(json.dumps(data))
        result = configure("uninstall", self.settings, self.project, agent="codex")
        self.assertEqual(result["status"], "uninstalled")
        restored = json.loads(self.settings.read_text())
        self.assertEqual(restored["new_user_value"], 42)
        self.assertIn("Stop", restored["hooks"])

    def test_codex_install_is_idempotent(self):
        configure("install", self.settings, self.project, agent="codex")
        before = self.settings.read_bytes()
        self.assertEqual(configure("install", self.settings, self.project, agent="codex")["status"], "already_installed")
        self.assertEqual(self.settings.read_bytes(), before)

    def test_doctor_rejects_codex_async_wrong_command_and_schema_mixups(self):
        configure("install", self.settings, self.project, agent="codex")
        original = self.settings.read_text()
        for edit in ({"async": True}, {"command": "inert-untrusted-command"}, {"onFailure": "block"}):
            data = json.loads(original)
            data["hooks"]["PreToolUse"][0]["hooks"][0].update(edit)
            self.settings.write_text(json.dumps(data))
            with patch("protection_agency.integration.subprocess.run") as run:
                result = inspect_configuration(self.settings, self.project, agent="codex", probe=True)
            self.assertEqual(result["status"], "modified")
            run.assert_not_called()

    def test_codex_project_hook_disabling_blocks_install_and_scan(self):
        config = self.project / ".codex/config.toml"
        config.parent.mkdir()
        config.write_text('[features]\nhooks = false\n')
        self.assertEqual(configure("install", self.settings, self.project, agent="codex")["status"], "disabled_by_agent_settings")
        findings, gaps = inspect(".codex/config.toml", config.read_text())
        self.assertFalse(gaps)
        self.assertIn("PA409", {f.rule for f in findings})
        self.assertFalse(self.settings.parent.exists())

    def test_codex_user_controls_are_checked_without_editing_toml(self):
        self.settings.parent.mkdir()
        config = self.settings.parent / "config.toml"
        for original in ('[features]\ncodex_hooks = false\n', 'allow_managed_hooks_only = true\n'):
            config.write_text(original)
            self.assertEqual(configure("install", self.settings, self.project, agent="codex")["status"], "disabled_by_agent_settings")
            self.assertEqual(config.read_text(), original)

    def test_invalid_codex_controls_are_not_silently_ignored(self):
        for source in ('[features]\nhooks = "false"', 'allow_managed_hooks_only = "true"', '[features\n'):
            _, gaps = inspect(".codex/config.toml", source)
            self.assertTrue(gaps)

    def test_codex_startup_surfaces_include_inline_hooks_and_mcp(self):
        source = '[mcp_servers.example]\ncommand="echo inert"\n[[hooks.SessionStart]]\n[[hooks.SessionStart.hooks]]\ntype="command"\ncommand="echo inert"\n'
        findings, gaps = inspect(".codex/config.toml", source)
        self.assertFalse(gaps)
        self.assertTrue({"PA400", "PA402"} <= {f.rule for f in findings})

    def test_cli_setup_requires_explicit_adapter_for_noninteractive_preview(self):
        result = self.cli("setup", "--dry-run", "--settings", self.settings)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Choose --agent", result.stdout)
        self.assertFalse(self.settings.parent.exists())

    def test_guided_setup_selects_codex_and_discloses_strict_failure_policy(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        output = io.StringIO()
        status = setup(self.project, settings=self.settings, online=False, agent=None,
                       input_stream=Terminal("codex\nyes\n"), output_stream=output)
        self.assertEqual(status, 0, output.getvalue())
        self.assertIn("strict shell adapter", output.getvalue())
        self.assertIn("errors/timeouts may continue", output.getvalue())
        self.assertIn("not verified", output.getvalue())

    def test_cli_codex_demo_works_without_native_client(self):
        result = self.cli("demo", "--agent", "codex", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["agent"], "codex")

    def test_open_requires_adapter_or_explicit_client(self):
        output = io.StringIO()
        self.assertEqual(open_client(self.project, agent=None, output_stream=output), 2)
        self.assertIn("--agent codex", output.getvalue())
        if os.name != "nt":
            with patch.dict(os.environ, {"SHELL": str(self.project / "untrusted-shell")}):
                with self.assertRaises(ValueError):
                    open_client(self.project, agent="codex", output_stream=io.StringIO())

    @unittest.skipIf(os.name == "nt", "Windows native discovery is tested separately")
    def test_codex_discovery_uses_selected_name_and_sanitized_path(self):
        with patch("protection_agency.onboarding.shutil.which", return_value=None) as which:
            self.assertEqual(open_client(self.project, agent="codex", output_stream=io.StringIO()), 3)
        self.assertEqual(which.call_args.args[0], "codex")
