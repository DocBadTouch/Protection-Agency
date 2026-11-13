"""First-time workflows use temporary profiles and inert trusted clients only."""
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from protection_agency import onboarding
from protection_agency.models import Finding, Report
from protection_agency.presentation import doctor_result, launch_receipt, scan_result, setup_result

SOURCE = Path(__file__).resolve().parents[1]


class Terminal(io.StringIO):
    def isatty(self):
        return True


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pa-onboarding-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        (self.project / ".git").mkdir()
        (self.project / ".git/config").write_text("[core]\nrepositoryformatversion = 0\n")
        self.settings = self.base / "profile/settings.json"
        self.output = io.StringIO()

    def setup(self, answers="y\n", *, terminal=True, **kwargs):
        return onboarding.setup(self.project, settings=self.settings, online=kwargs.pop("online", False),
                                input_stream=Terminal(answers) if terminal else io.StringIO(answers),
                                output_stream=self.output, **kwargs)

    def cli(self, *args, cwd=None):
        return subprocess.run([sys.executable, "-I", str(SOURCE / "guard.py"), *map(str, args)],
                              cwd=cwd or self.project, capture_output=True, text=True, timeout=15)

    def client(self):
        marker = self.base / "client-marker.json"
        script = self.base / "inert-client.py"
        script.write_text("import json, os, sys\nfrom pathlib import Path\nPath(" + repr(str(marker)) +
                          ").write_text(json.dumps({'cwd': os.getcwd(), 'args': sys.argv[1:]}))\n")
        return marker, script

    def test_guided_setup_installs_only_after_consent_and_probes_it(self):
        self.settings.parent.mkdir(mode=0o700)
        self.settings.write_text('{"theme":"dark"}')
        self.settings.chmod(0o600)
        self.assertEqual(self.setup(), 0)
        data = json.loads(self.settings.read_text())
        self.assertEqual(data["theme"], "dark")
        self.assertIn("SessionStart", data["hooks"])
        text = self.output.getvalue()
        self.assertIn("Install these two hook groups", text)
        self.assertIn("Trusted hook response test: passed", text)
        self.assertIn("enforcement remains unverified", text)
        self.assertNotIn("--online", data["hooks"]["PreToolUse"][0]["hooks"][0]["args"])
        self.assertTrue(list(self.settings.parent.glob("*.bak")))

    def test_online_hooks_require_explicit_choice(self):
        self.assertEqual(self.setup("yes\nyes\n", online=None), 0)
        data = json.loads(self.settings.read_text())
        self.assertIn("--online", data["hooks"]["PreToolUse"][0]["hooks"][0]["args"])
        self.assertIn("send eligible public package", self.output.getvalue())

    def test_empty_online_answer_chooses_offline(self):
        self.assertEqual(self.setup("\ny\n", online=None), 0)
        data = json.loads(self.settings.read_text())
        self.assertNotIn("--online", data["hooks"]["PreToolUse"][0]["hooks"][0]["args"])

    def test_decline_or_eof_leaves_profile_absent(self):
        for answer in ("n\n", "", "yes-but-not-really\n"):
            with self.subTest(answer=answer):
                self.assertEqual(self.setup(answer), 2)
                self.assertFalse(self.settings.parent.exists())

    def test_setup_does_not_accept_piped_consent(self):
        self.assertEqual(self.setup("yes\n", terminal=False), 2)
        self.assertFalse(self.settings.parent.exists())
        self.assertIn("needs a terminal", self.output.getvalue())

    def test_dry_run_is_noninteractive_and_does_not_create_files(self):
        with patch("protection_agency.onboarding.diagnose") as diagnose:
            self.assertEqual(self.setup(terminal=False, online=None, dry_run=True), 0)
        diagnose.assert_not_called()
        self.assertFalse(self.settings.parent.exists())
        self.assertIn("offline", self.output.getvalue())

    def test_wizard_detects_profile_changed_during_confirmation(self):
        self.settings.parent.mkdir(mode=0o700)
        self.settings.write_text('{"theme":"dark"}')
        self.settings.chmod(0o600)
        settings = self.settings

        class EditingTerminal(Terminal):
            def readline(self, limit=-1):
                settings.write_text('{"theme":"changed-by-user"}')
                return "y\n"

        result = onboarding.setup(self.project, settings=self.settings, online=False,
                                  input_stream=EditingTerminal(), output_stream=self.output)
        self.assertEqual(result, 2)
        self.assertEqual(json.loads(self.settings.read_text()), {"theme": "changed-by-user"})
        self.assertFalse(list(self.settings.parent.glob("*.bak")))

    def test_setup_refuses_project_hook_disabling_without_changing_it(self):
        config = self.project / ".claude/settings.json"
        config.parent.mkdir()
        original = '{"disableAllHooks":true}'
        config.write_text(original)
        self.assertEqual(self.setup(), 2)
        self.assertFalse(self.settings.parent.exists())
        self.assertEqual(config.read_text(), original)

    def test_setup_refuses_unsafe_user_profile(self):
        self.settings.parent.mkdir(mode=0o700)
        target = self.base / "unrelated-settings.json"
        target.write_text('{}')
        self.settings.symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            self.setup()
        self.assertEqual(target.read_text(), '{}')

    def test_custom_profile_environment_is_used_and_explicit_path_wins(self):
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.base / "custom-profile")}):
            self.assertEqual(onboarding.settings_path(), self.base / "custom-profile/settings.json")
            self.assertEqual(onboarding.settings_path(self.settings), self.settings)
            status = onboarding.setup(self.project, online=False, dry_run=True, output_stream=self.output)
        self.assertEqual(status, 0)
        self.assertIn("custom-profile", self.output.getvalue())
        self.assertFalse((self.base / "custom-profile").exists())

    def test_project_contained_global_config_is_rejected_before_writing(self):
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.project)}):
            with self.assertRaises(ValueError):
                self.setup()
        self.assertFalse(self.settings.parent.exists())

    def test_failed_local_probe_does_not_claim_success_or_restore_old_settings(self):
        with patch("protection_agency.onboarding.inspect_configuration", return_value={"status": "configured", "probe": "failed"}):
            self.assertEqual(self.setup(), 2)
        self.assertTrue(self.settings.exists())
        self.assertIn("could not verify", self.output.getvalue())
        self.assertNotIn("Local configuration and response tests passed", self.output.getvalue())

    def test_setup_shortcut_is_shell_quoted_and_not_persisted(self):
        self.assertEqual(self.setup(), 0)
        alias = next(line for line in self.output.getvalue().splitlines() if line.startswith("alias agency="))
        tokens = shlex.split(alias)
        argv = shlex.split(tokens[1].split("=", 1)[1])
        self.assertEqual(argv[0], str(Path(sys.executable).resolve()))
        self.assertEqual(argv[1:], ["-I", str(SOURCE / "guard.py")])
        self.assertEqual(set(self.base.iterdir()), {self.project, self.settings.parent})

    def test_shell_hints_quote_metacharacters_and_hide_control_characters(self):
        args = ["agency", "check", "a path; $(do-not-run) 'quoted'"]
        self.assertEqual(shlex.split(onboarding._shell_line(args)), args)
        self.assertNotIn("\x1b", onboarding._shell_line(["agency", "bad\x1b[2Jpath"]))

    def test_demo_uses_only_trusted_hook_and_no_original_project_commands(self):
        marker = self.project / "executed"
        (self.project / "sitecustomize.py").write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()")
        result = self.cli("demo", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "passed")
        self.assertEqual(len(data["checks"]), 3)
        self.assertFalse(data["project_commands_executed"])
        self.assertFalse(data["network_requests"])
        self.assertFalse(marker.exists())
        self.assertEqual(data["live_client_enforcement"], "not_verified")

    def test_demo_failure_does_not_print_a_success_message(self):
        self.assertIn("demonstration failed", onboarding.demo_text({"status": "failed"}))
        self.assertNotIn("BLOCKED by the guard", onboarding.demo_text({"status": "failed"}))

    def test_check_defaults_to_cwd_and_preserves_json_option(self):
        readable = self.cli("check")
        self.assertEqual(readable.returncode, 2)
        self.assertIn("Current vulnerability advisories were not checked", readable.stdout)
        self.assertIn("No project commands were executed", readable.stdout)
        machine = self.cli("check", "--json")
        self.assertEqual(machine.returncode, 2)
        self.assertEqual(json.loads(machine.stdout)["decision"], "review")

    def test_check_explains_published_malicious_version_and_next_step(self):
        (self.project / "package.json").write_text('{"dependencies":{"cdeops":"13.5.31"}}')
        result = self.cli("check")
        self.assertEqual(result.returncode, 1)
        self.assertIn("STOP:", result.stdout)
        self.assertIn("cdeops@13.5.31", result.stdout)
        self.assertIn("Next:", result.stdout)

    def test_setup_cli_preview_and_noninteractive_refusal(self):
        preview = self.cli("setup", "--settings", self.settings, "--dry-run")
        self.assertEqual(preview.returncode, 0, preview.stderr)
        blocked = self.cli("setup", "--settings", self.settings, "--online")
        self.assertEqual(blocked.returncode, 2)
        self.assertFalse(self.settings.parent.exists())
        self.settings.parent.mkdir(mode=0o700)
        self.settings.write_text('{}')
        self.settings.chmod(0o666)
        unsafe = self.cli("setup", "--settings", self.settings, "--dry-run")
        self.assertEqual(unsafe.returncode, 3)
        self.assertIn("not writable by other users", unsafe.stderr)
        self.assertNotIn("inert-secret", onboarding.error_hint(ValueError("inert-secret")))

    def test_doctor_and_removal_have_explicit_readable_modes(self):
        self.setup()
        result = self.cli("doctor", "--root", self.project, "--settings", self.settings, "--probe-hooks", "--human")
        self.assertEqual(result.returncode, 0)
        self.assertIn("8/8 passed", result.stdout)
        self.assertIn("Native Claude enforcement: not verified", result.stdout)
        result = self.cli("uninstall-hooks", "--project", self.project, "--settings", self.settings, "--human")
        self.assertEqual(result.returncode, 0)
        self.assertIn("hooks removed", result.stdout)

    def test_open_requires_external_absolute_client(self):
        marker = self.project / "executed"
        client = self.project / "claude"
        client.write_text("#!/bin/sh\ntouch " + shlex.quote(str(marker)) + "\n")
        client.chmod(0o700)
        for path in ("claude", str(client)):
            self.assertEqual(onboarding.open_client(self.project, client=path, online=True, output_stream=self.output), 3)
        self.assertFalse(marker.exists())

    def test_open_auto_discovery_ignores_project_and_relative_path_entries(self):
        fake_bin = self.project / "bin"
        fake_bin.mkdir()
        with patch.dict(os.environ, {"PATH": str(fake_bin) + ":.:/usr/bin"}):
            with patch("protection_agency.onboarding.shutil.which", return_value=None) as which:
                status = onboarding.open_client(self.project, output_stream=self.output)
        self.assertEqual(status, 3)
        self.assertEqual(which.call_args.kwargs["path"], str(Path("/usr/bin").resolve()))

    def test_open_rejects_external_symlink_to_project_client(self):
        target = self.project / "claude"
        target.write_text("#!/bin/sh\nexit 0\n")
        target.chmod(0o700)
        (self.base / "claude").symlink_to(target)
        with patch("protection_agency.onboarding.shutil.which", return_value=str(self.base / "claude")):
            self.assertEqual(onboarding.open_client(self.project, online=True, output_stream=self.output), 3)

    def test_open_starts_literal_client_after_gate_and_preserves_arguments(self):
        marker, script = self.client()
        literal = "$(touch should-not-run); 'literal'"
        status = onboarding.open_client(self.project, client=sys.executable, online=True,
                                        client_args=["-I", str(script), literal], output_stream=self.output)
        self.assertEqual(status, 0, self.output.getvalue())
        data = json.loads(marker.read_text())
        self.assertEqual(data["cwd"], str(self.project))
        self.assertEqual(data["args"], [literal])
        self.assertIn("Starting the selected client", self.output.getvalue())
        self.assertNotIn('"snapshot_id"', self.output.getvalue())

    def test_open_offline_and_dry_run_do_not_execute_client(self):
        marker, script = self.client()
        self.assertEqual(onboarding.open_client(self.project, client=sys.executable, client_args=["-I", str(script)],
                         output_stream=self.output), 2)
        self.assertFalse(marker.exists())
        self.assertEqual(onboarding.open_client(self.project, client=sys.executable, online=True, dry_run=True,
                         client_args=["-I", str(script)], output_stream=self.output), 0)
        self.assertFalse(marker.exists())

    def test_open_blocks_malicious_release_before_executing_client(self):
        marker, script = self.client()
        (self.project / "package.json").write_text('{"dependencies":{"cdeops":"13.5.31"}}')
        status = onboarding.open_client(self.project, client=sys.executable, online=True,
                                        client_args=["-I", str(script)], output_stream=self.output)
        self.assertEqual(status, 1)
        self.assertFalse(marker.exists())
        self.assertIn("Client not started", self.output.getvalue())

    def test_open_cli_passes_client_arguments_after_separator(self):
        marker, script = self.client()
        result = self.cli("open", "--client", sys.executable, "--online", "--", "-I", script, "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(marker.read_text())["args"], ["--help"])
        self.assertIn("startup check", result.stderr)

    def test_human_results_sanitize_terminal_metadata(self):
        report = Report("standard", False)
        report.findings.append(Finding("TEST", "medium", "bad\x1b[2Jpath.py", 1, "Example", "Inspect the example."))
        report.gap("missing\x1b]52;clipboard")
        text = scan_result(report)
        self.assertNotIn("\x1b", text)
        self.assertIn("legitimate code can also match", text)

    def test_human_results_bound_default_findings_and_explain_gaps(self):
        report = Report("standard", True, advisories="failed")
        for index in range(7):
            report.findings.append(Finding("TEST", "medium", f"{index}.py", 1, "Example", "Inspect the example."))
        report.gap("Unsupported inventory")
        self.assertEqual(scan_result(report).count("[MEDIUM]"), 5)
        self.assertEqual(scan_result(report, full=True).count("[MEDIUM]"), 7)
        self.assertIn("Advisory coverage is incomplete", scan_result(report))
        self.assertIn("Unsupported inventory", scan_result(report))

    def test_no_findings_and_applied_warning_do_not_overclaim(self):
        text = scan_result(Report("standard", True, advisories="complete"))
        self.assertIn("not a guarantee", text)
        self.assertNotIn("safe to run", text.lower())
        text = setup_result({"status": "applied_with_warning", "changed": True})
        self.assertIn("Settings were changed", text)
        incomplete = Report("standard", True, advisories="complete", inventory="incomplete")
        self.assertIn("Client not started", launch_receipt({"report": incomplete.summary()}))

    def test_readable_terminal_review_keeps_all_finding_metadata(self):
        finding = Finding("TEST", "medium", "path.py", 1, "Example", "Review it", reference="https://example.org/advisory", package="example", version="1.0.0").detail()
        text = launch_receipt({"review_findings": [finding], "execution": "not_started"})
        for value in finding.values():
            self.assertIn(str(value), text.lower() if value == "medium" else text)

    def test_demo_timeout_reports_failure_without_captured_data(self):
        with patch("protection_agency.onboarding.probe_protocol", side_effect=subprocess.TimeoutExpired("inert-secret", 5)):
            result = onboarding.demo()
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("inert-secret", json.dumps(result))

    def test_setup_self_check_failure_leaves_profile_absent(self):
        failure = {"status": "failed", "checks": [{"check": "runtime", "status": "failed"}], "warnings": []}
        with patch("protection_agency.onboarding.diagnose", return_value=failure):
            self.assertEqual(self.setup(), 3)
        self.assertFalse(self.settings.parent.exists())

    def test_real_terminal_setup_waits_for_consent_before_writing(self):
        import pty
        import select
        master, slave = pty.openpty()
        process = None
        try:
            process = subprocess.Popen([sys.executable, "-I", str(SOURCE / "guard.py"), "setup", str(self.project),
                "--settings", str(self.settings), "--offline"], stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            observed = b""
            for _ in range(20000):
                ready, _, _ = select.select([process.stdout], [], [], 5)
                self.assertTrue(ready, "setup prompt timed out")
                chunk = os.read(process.stdout.fileno(), 1)
                self.assertTrue(chunk, "setup ended before consent")
                observed += chunk
                if b"Install these two hook groups" in observed and observed.endswith(b"[y/N] "):
                    break
            else:
                self.fail("setup confirmation was not shown")
            self.assertFalse(self.settings.exists())
            os.write(master, b"yes\n")
            remaining, errors = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, errors.decode())
            self.assertTrue(self.settings.exists())
            self.assertIn(b"Trusted hook response test: passed", observed + remaining)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            os.close(master)
            os.close(slave)

    def test_real_terminal_open_preserves_the_review_challenge(self):
        import pty
        import re
        import select
        config = self.project / ".claude/settings.json"
        config.parent.mkdir()
        config.write_text('{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo inert"}]}]}}')
        marker, script = self.client()
        master, slave = pty.openpty()
        process = None
        try:
            process = subprocess.Popen([sys.executable, "-I", str(SOURCE / "guard.py"), "open", str(self.project),
                "--client", sys.executable, "--online", "--review", "--", "-I", str(script)],
                stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            observed = b""
            for _ in range(20000):
                ready, _, _ = select.select([process.stderr], [], [], 5)
                self.assertTrue(ready, "open challenge timed out")
                chunk = os.read(process.stderr.fileno(), 1)
                self.assertTrue(chunk, "open ended before review")
                observed += chunk
                challenge = re.search(rb"Review challenge: (APPROVE [0-9a-f]{12})\n", observed)
                if challenge:
                    break
            else:
                self.fail("open terminal challenge was not shown")
            self.assertFalse(marker.exists())
            self.assertIn(b"PA400", observed)
            self.assertIn(b"execution_surface", observed)
            os.write(master, challenge[1] + b"\n")
            _, remaining = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, (observed + remaining).decode())
            self.assertTrue(marker.exists())
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            os.close(master)
            os.close(slave)
