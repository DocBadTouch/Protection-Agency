"""Integration setup tests only edit owned temporary files and run trusted hooks."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from protection_agency.scanner import Scanner
from protection_agency.osv import OSVClient

PROJECT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == "nt", "POSIX permissions/locks contract; native Windows parity is in test_windows")
class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pa-integration-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "untrusted-project"
        self.project.mkdir()
        self.settings = self.base / "trusted-config" / "settings.json"

    def configure(self, operation="install", **kwargs):
        from protection_agency.integration import configure
        return configure(operation, self.settings, self.project, **kwargs)

    def write(self, data):
        self.settings.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.settings.write_text(data if isinstance(data, str) else json.dumps(data))
        self.settings.chmod(0o600)

    def test_install_adds_guard_hooks_and_preserves_other_settings(self):
        other = {"type": "command", "command": "echo unrelated"}
        self.write({"theme": "dark", "hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [other]}]}})
        result = self.configure(online=True)
        data = json.loads(self.settings.read_text())
        self.assertEqual(result["status"], "installed")
        self.assertEqual(data["theme"], "dark")
        self.assertEqual(data["hooks"]["PreToolUse"][0]["hooks"], [other])
        guard = data["hooks"]["PreToolUse"][-1]["hooks"][0]
        self.assertEqual(guard["onFailure"], "block")
        self.assertEqual(guard["args"][0], "-I")
        self.assertIn("--online", guard["args"])
        self.assertTrue(Path(guard["command"]).is_absolute())
        self.assertFalse(Path(guard["args"][1]).is_relative_to(self.project))

    def test_install_is_idempotent_without_new_backups(self):
        self.configure()
        before = self.settings.read_bytes()
        backups = list(self.settings.parent.glob("*.bak"))
        result = self.configure()
        self.assertEqual(result["status"], "already_installed")
        self.assertEqual(self.settings.read_bytes(), before)
        self.assertEqual(list(self.settings.parent.glob("*.bak")), backups)

    def test_dry_run_does_not_create_configuration_or_parent(self):
        result = self.configure(dry_run=True)
        self.assertEqual(result["status"], "would_install")
        self.assertFalse(self.settings.parent.exists())

    def test_uninstall_preserves_settings_added_after_install(self):
        self.write({"theme": "dark"})
        self.configure()
        data = json.loads(self.settings.read_text())
        data["language"] = "en"
        data["hooks"]["Stop"] = [{"hooks": [{"type": "command", "command": "echo user-added"}]}]
        self.settings.write_text(json.dumps(data))
        result = self.configure("uninstall")
        data = json.loads(self.settings.read_text())
        self.assertEqual(result["status"], "uninstalled")
        self.assertEqual(data["theme"], "dark")
        self.assertEqual(data["language"], "en")
        self.assertEqual(data["hooks"]["Stop"][0]["hooks"][0]["command"], "echo user-added")
        self.assertNotIn("SessionStart", data["hooks"])
        self.assertNotIn("PreToolUse", data["hooks"])

    def test_disabled_hooks_are_not_silently_enabled(self):
        self.write({"disableAllHooks": True, "theme": "dark"})
        before = self.settings.read_bytes()
        result = self.configure()
        self.assertEqual(result["status"], "disabled")
        self.assertEqual(self.settings.read_bytes(), before)

    def test_private_backup_retains_exact_original_bytes(self):
        original = b'{ // user comment\n "apiKey": "inert-private-value", "theme": "dark",\n}\n'
        self.write(original.decode())
        result = self.configure()
        backup = self.settings.parent / result["backup"]
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.settings.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("inert-private-value", json.dumps(result))

    def test_configuration_inside_project_is_rejected(self):
        from protection_agency.integration import configure
        with self.assertRaises((OSError, ValueError)):
            configure("install", self.project / ".claude/settings.json", self.project)
        self.assertFalse((self.project / ".claude").exists())

    def test_duplicate_json_keys_are_not_overwritten(self):
        self.write('{"theme":"dark","theme":"light"}')
        before = self.settings.read_bytes()
        with self.assertRaises((OSError, ValueError)):
            self.configure()
        self.assertEqual(self.settings.read_bytes(), before)

    def test_project_cannot_silently_disable_global_hooks(self):
        config = self.project / ".claude/settings.json"
        config.parent.mkdir()
        config.write_text('{"disableAllHooks":true}')
        client = OSVClient(lambda queries, timeout: {"results": [{} for _ in queries]})
        report = Scanner(self.project, online=True, osv_client=client).scan()
        self.assertEqual(report.decision, "block")
        self.assertIn("PA408", {f.rule for f in report.findings})

    def test_doctor_can_probe_installed_trusted_guard(self):
        self.configure(online=True)
        result = subprocess.run([sys.executable, "-I", str(PROJECT / "guard.py"), "doctor",
            "--root", str(self.project), "--settings", str(self.settings), "--probe-hooks"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["integration"]["status"], "configured")
        self.assertEqual(data["integration"]["probe"], "passed")
        self.assertEqual(data["live_client_enforcement"], "not_verified")

    def test_doctor_detects_tampered_failure_policy_without_running_it(self):
        self.configure()
        data = json.loads(self.settings.read_text())
        data["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"] = "continue"
        self.settings.write_text(json.dumps(data))
        from protection_agency.integration import inspect_configuration
        result = inspect_configuration(self.settings, self.project, probe=True)
        self.assertEqual(result["status"], "modified")
        self.assertEqual(result["probe"], "not_run")

    def test_invalid_settings_leave_original_untouched(self):
        cases = ['[]', '{', '{"hooks":[]}', '{"hooks":{"Stop":{}}}',
                 '{"hooks":{"Stop":[{"hooks":"echo"}]}}',
                 '{"disableAllHooks":"false"}',
                 '{"hooks":{"Stop":[{"hooks":[],"matcher":1}]}}',
                 '{"hooks":{},"nested":{"same":1,"same":2}}',
                 '{"unsupported":NaN}', '{"unsupported":1e999}',
                 '{"unsupported":' + '[' * 65 + '0' + ']' * 65 + '}']
        for original in cases:
            with self.subTest(original=original):
                self.write(original)
                with self.assertRaises((OSError, ValueError)):
                    self.configure()
                self.assertEqual(self.settings.read_text(), original)
                self.assertEqual(list(self.settings.parent.glob("*.bak")), [])

    def test_unsafe_settings_paths_are_refused_without_writes(self):
        from protection_agency.integration import configure
        target = self.base / "original.json"
        target.write_text('{}')
        target.chmod(0o600)
        for case in ("symlink_file", "symlink_parent", "hardlink", "writable_file", "writable_parent"):
            with self.subTest(case=case):
                parent = self.base / case
                parent.mkdir(mode=0o700)
                settings = parent / "settings.json"
                if case == "symlink_file":
                    settings.symlink_to(target)
                elif case == "symlink_parent":
                    alias = self.base / "alias"
                    alias.symlink_to(parent, target_is_directory=True)
                    settings = alias / "settings.json"
                elif case == "hardlink":
                    os.link(target, settings)
                else:
                    settings.write_text('{}')
                    settings.chmod(0o666 if case == "writable_file" else 0o600)
                    if case == "writable_parent":
                        parent.chmod(0o777)
                with self.assertRaises((OSError, ValueError)):
                    configure("install", settings, self.project)
                self.assertEqual(target.read_text(), '{}')
                self.assertEqual(list(parent.glob("*.bak")), [])

    def test_uninstall_missing_and_dry_run_do_not_edit_settings(self):
        self.assertEqual(self.configure("uninstall")["status"], "not_installed")
        self.assertFalse(self.settings.parent.exists())
        self.configure()
        before = self.settings.read_bytes()
        files = set(self.settings.parent.iterdir())
        self.assertEqual(self.configure("uninstall", dry_run=True)["status"], "would_uninstall")
        self.assertEqual(self.settings.read_bytes(), before)
        self.assertEqual(set(self.settings.parent.iterdir()), files)

    def test_legacy_hooks_are_adopted_and_unrelated_empty_groups_preserved(self):
        from protection_agency.integration import _handler, _locations
        _, _, python, launcher = _locations(self.settings, self.project)
        data = {"hooks": {"Stop": [], "Notification": [{"hooks": []}]}}
        for event in ("SessionStart", "PreToolUse"):
            handler = _handler(event, python, launcher, True)
            handler.pop("statusMessage")
            group = {"hooks": [handler]}
            if event == "PreToolUse":
                group["matcher"] = "Bash"
            data["hooks"][event] = [group]
        self.write(data)
        self.configure(online=True)
        installed = json.loads(self.settings.read_text())
        self.assertEqual(len(installed["hooks"]["PreToolUse"]), 1)
        self.configure("uninstall")
        self.assertEqual(json.loads(self.settings.read_text()),
                         {"hooks": {"Stop": [], "Notification": [{"hooks": []}]}})

    def test_installer_repairs_only_marked_hooks_on_explicit_request(self):
        self.configure()
        data = json.loads(self.settings.read_text())
        data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = "/untrusted/changed"
        other = {"type": "command", "command": "echo unrelated"}
        data["hooks"]["PreToolUse"][0]["hooks"].append(other)
        self.write(data)
        self.configure()
        data = json.loads(self.settings.read_text())
        self.assertEqual(data["hooks"]["PreToolUse"][0]["hooks"], [other])
        self.assertNotEqual(data["hooks"]["PreToolUse"][-1]["hooks"][0]["command"], "/untrusted/changed")

    def test_doctor_rejects_modified_profiles_without_executing_any_command(self):
        from protection_agency.integration import inspect_configuration
        self.configure()
        original = json.loads(self.settings.read_text())
        mutations = [lambda d: d["hooks"]["PreToolUse"][0]["hooks"][0].update(command="/untrusted/guard"),
                     lambda d: d["hooks"]["PreToolUse"][0]["hooks"][0].update({"async": True}),
                     lambda d: d["hooks"]["PreToolUse"][0]["hooks"][0].update(timeout=1),
                     lambda d: d["hooks"]["PreToolUse"][0].update(matcher="Read"),
                     lambda d: d["hooks"]["SessionStart"][0].update(matcher="startup"),
                     lambda d: d["hooks"]["PreToolUse"].append(d["hooks"]["PreToolUse"][0]),
                     lambda d: d["hooks"]["PreToolUse"][0]["hooks"][0]["args"].append("--online")]
        for change in mutations:
            data = json.loads(json.dumps(original))
            change(data)
            self.write(data)
            with patch("protection_agency.integration.subprocess.run") as run:
                result = inspect_configuration(self.settings, self.project, probe=True)
            self.assertEqual(result["status"], "modified")
            run.assert_not_called()

    def test_probe_does_not_run_unrelated_hooks_or_project_python_startup(self):
        from protection_agency.integration import inspect_configuration
        marker = self.project / "executed"
        payload = "from pathlib import Path; Path(" + repr(str(marker)) + ").touch()"
        (self.project / "sitecustomize.py").write_text(payload)
        self.write({"apiKey": "inert-secret", "hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": sys.executable, "args": ["-c", payload]}]}]}})
        self.configure(online=True)
        result = inspect_configuration(self.settings, self.project, probe=True)
        self.assertEqual(result["probe"], "passed")
        self.assertFalse(marker.exists())
        self.assertNotIn("inert-secret", json.dumps(result))
        self.assertEqual(result["live_client_enforcement"], "not_verified")
        self.assertEqual(result["client_version"], "not_checked")

    def test_doctor_reports_project_disablement_and_invalid_controls(self):
        from protection_agency.integration import inspect_configuration
        self.configure()
        config = self.project / ".claude/settings.local.json"
        config.parent.mkdir()
        for value, status in ((True, "disabled_by_project"), (False, "configured"), ("false", "unsafe_or_invalid")):
            with self.subTest(value=value):
                config.write_text(json.dumps({"disableAllHooks": value}))
                with patch("protection_agency.integration.subprocess.run") as run:
                    result = inspect_configuration(self.settings, self.project)
                self.assertEqual(result["status"], status)
                run.assert_not_called()

    def test_hook_probe_failures_are_reported_without_exposing_output(self):
        from protection_agency.integration import inspect_configuration
        self.configure()
        cases = [subprocess.TimeoutExpired("trusted-hook", 5),
                 subprocess.CompletedProcess([], 0, "inert-private-output", ""),
                 subprocess.CompletedProcess([], 0, "[]", ""),
                 subprocess.CompletedProcess([], 3, "{}", "")]
        for outcome in cases:
            with self.subTest(outcome=type(outcome).__name__):
                kwargs = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
                with patch("protection_agency.integration.subprocess.run", **kwargs):
                    result = inspect_configuration(self.settings, self.project, probe=True)
                self.assertEqual(result["probe"], "failed")
                self.assertNotIn("inert-private-output", json.dumps(result))

    def test_probe_detects_configuration_change_during_check(self):
        from protection_agency.integration import inspect_configuration
        self.configure()
        original = subprocess.run

        def changing_run(*args, **kwargs):
            result = original(*args, **kwargs)
            self.settings.write_text(self.settings.read_text() + " ")
            return result

        with patch("protection_agency.integration.subprocess.run", side_effect=changing_run):
            result = inspect_configuration(self.settings, self.project, probe=True)
        self.assertEqual(result["status"], "changed_during_check")
        self.assertEqual(result["probe"], "not_verified")

    def test_concurrent_configuration_edit_is_preserved(self):
        from protection_agency import config_io
        self.write({"theme": "dark"})
        original = config_io._write_new

        def concurrent_write(fd, name, raw):
            original(fd, name, raw)
            if name.endswith(".tmp"):
                self.settings.write_text('{"theme":"changed-by-user"}')

        with patch("protection_agency.config_io._write_new", side_effect=concurrent_write):
            result = self.configure()
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(json.loads(self.settings.read_text())["theme"], "changed-by-user")
        self.assertEqual(list(self.settings.parent.glob("*.tmp")), [])

    def test_directory_replacement_is_detected_before_commit(self):
        from protection_agency import config_io
        self.write({"theme": "dark"})
        original = config_io._write_new
        old_parent = self.base / "moved-config"

        def concurrent_move(fd, name, raw):
            original(fd, name, raw)
            if name.endswith(".tmp"):
                self.settings.parent.rename(old_parent)
                self.settings.parent.mkdir(mode=0o700)
                self.settings.write_text('{"theme":"replacement"}')

        with patch("protection_agency.config_io._write_new", side_effect=concurrent_move):
            result = self.configure()
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(json.loads(self.settings.read_text())["theme"], "replacement")
        self.assertEqual(list(old_parent.glob("*.tmp")), [])

    def test_active_and_unsafe_locks_prevent_writes(self):
        import fcntl
        self.write({"theme": "dark"})
        before = self.settings.read_bytes()
        lock_path = self.settings.parent / ".settings.json.protection-agency.lock"
        with lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.configure()
            self.assertEqual(result["status"], "conflict")
        lock_path.write_text("unrelated lock data")
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual(self.settings.read_bytes(), before)
        self.assertEqual(lock_path.read_text(), "unrelated lock data")

    def test_failed_atomic_replace_keeps_original_and_cleans_staging_file(self):
        self.write({"theme": "dark"})
        before = self.settings.read_bytes()
        with patch("protection_agency.config_io.os.replace", side_effect=OSError("inert disk failure")):
            with self.assertRaises(OSError):
                self.configure()
        self.assertEqual(self.settings.read_bytes(), before)
        self.assertEqual(list(self.settings.parent.glob("*.tmp")), [])
        self.assertEqual(next(self.settings.parent.glob("*.bak")).read_bytes(), before)

    def test_post_commit_sync_failure_reports_that_change_was_applied(self):
        original = os.fsync

        def failing_directory_sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("inert sync failure")
            return original(fd)

        with patch("protection_agency.config_io.os.fsync", side_effect=failing_directory_sync):
            result = self.configure()
        self.assertEqual(result["status"], "applied_with_warning")
        self.assertTrue(result["changed"])
        self.assertIn("hooks", json.loads(self.settings.read_text()))

    def test_oversized_original_and_expanded_settings_are_refused(self):
        from protection_agency.config_io import LIMIT
        for original in ('{"padding":"' + 'x' * LIMIT + '"}',
                         '{"padding":"' + 'x' * (LIMIT - 100) + '"}'):
            self.write(original)
            before = self.settings.read_bytes()
            with self.assertRaises(ValueError):
                self.configure()
            self.assertEqual(self.settings.read_bytes(), before)

    def test_project_hook_disable_control_is_typed_and_context_specific(self):
        from protection_agency.startup import inspect
        findings, gaps = inspect(".claude/settings.json", '{"disableAllHooks":false}')
        self.assertFalse(findings)
        self.assertFalse(gaps)
        findings, gaps = inspect(".claude/settings.local.json", '{"disableAllHooks":"false"}')
        self.assertTrue(gaps)
        findings, gaps = inspect(".vscode/settings.json", '{"disableAllHooks":true}')
        self.assertNotIn("PA408", {f.rule for f in findings})

    def test_setup_and_doctor_cli_require_explicit_inputs(self):
        for args in (["install-hooks"], ["doctor", "--settings", str(self.settings)],
                     ["doctor", "--probe-hooks"]):
            result = subprocess.run([sys.executable, "-I", str(PROJECT / "guard.py"), *args],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
        self.assertFalse(self.settings.parent.exists())

    def test_install_refuses_a_project_that_explicitly_disables_hooks(self):
        config = self.project / ".claude/settings.json"
        config.parent.mkdir()
        config.write_text('{"disableAllHooks":true}')
        result = self.configure()
        self.assertEqual(result["status"], "disabled_by_project")
        self.assertFalse(self.settings.parent.exists())

    def test_install_and_uninstall_cli_use_the_selected_external_settings(self):
        for command, status in (("install-hooks", "installed"), ("uninstall-hooks", "uninstalled")):
            result = subprocess.run([sys.executable, "-I", str(PROJECT / "guard.py"), command,
                "--project", str(self.project), "--settings", str(self.settings)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], status)
        self.assertEqual(json.loads(self.settings.read_text()), {})
