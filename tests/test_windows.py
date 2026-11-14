"""Mandatory native NTFS security checks, independent of POSIX-only suites."""
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
from protection_agency.config_io import snapshot
from protection_agency.filesystem import read_project_file, directory_entries
from protection_agency.integration import configure, inspect_configuration, _handler, _locations
from protection_agency.onboarding import setup, open_client
from protection_agency.scanner import Scanner

SOURCE = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "nt", "native Windows APIs")
class WindowsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pa-windows-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        (self.project / ".git").mkdir()
        (self.project / ".git/config").write_text('[core]\nrepositoryformatversion = 0\n')
        self.settings = self.base / "profile/settings.json"

    def junction(self, link, target):
        cmd = Path(os.environ["SystemRoot"]) / "System32/cmd.exe"
        result = subprocess.run([str(cmd), "/d", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.addCleanup(lambda: os.rmdir(link) if link.exists() else None)

    def test_ntfs_reader_handles_unicode_and_spaces(self):
        folder = self.project / "space ünicode"
        folder.mkdir()
        (folder / "app.js").write_bytes(b'const value = 42;')
        self.assertEqual(read_project_file(self.project, "space ünicode/app.js", 1024), b'const value = 42;')
        self.assertEqual(Scanner(self.project).scan().files, 1)

    def test_directory_enumeration_uses_native_handle(self):
        (self.project / "app.js").write_text('const value = 42;')
        with directory_entries(self.project) as entries:
            self.assertEqual({entry.name for entry in entries}, {".git", "app.js"})

    def test_junction_content_is_not_read_and_scan_reports_gap(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret.js").write_text('inert-private-content')
        self.junction(self.project / "redirect", outside)
        with self.assertRaises(OSError):
            read_project_file(self.project, "redirect/secret.js", 1024)
        report = Scanner(self.project).scan()
        self.assertTrue(report.gaps)
        self.assertEqual(report.files, 0)

    def test_root_junction_is_refused(self):
        alias = self.base / "alias"
        self.junction(alias, self.project)
        with self.assertRaises(OSError):
            Scanner(alias)

    def test_relative_escape_devices_streams_and_network_paths_are_refused(self):
        for relative in ('../outside', r'\outside', r'C:outside', r'\\server\share\file', 'file:secret', 'NUL', 'name.'):
            with self.subTest(relative=relative), self.assertRaises(OSError):
                read_project_file(self.project, relative, 1024)

    def test_read_budget_and_special_objects_are_refused(self):
        (self.project / "large.js").write_bytes(b'x' * 50)
        with self.assertRaises(OSError):
            read_project_file(self.project, "large.js", 10)
        with self.assertRaises(OSError):
            read_project_file(self.project, ".git", 1024)

    def test_native_install_creates_private_acl_and_original_byte_backup(self):
        from protection_agency import windows_files as win
        self.settings.parent.mkdir()
        original = b'{ // comment\n "privateValue":"inert-secret", "theme":"dark",\n}\n'
        self.settings.write_bytes(original)
        result = configure("install", self.settings, self.project)
        self.assertEqual(result["status"], "installed")
        backup = self.settings.parent / result["backup"]
        self.assertEqual(backup.read_bytes(), original)
        self.assertNotIn("inert-secret", json.dumps(result))
        with win.pin_directory(self.settings.parent) as parent:
            for name in (self.settings.name, backup.name):
                handle = win.open_relative(parent, name, 0x80000000)
                try:
                    self.assertTrue(win.owner_and_acl(handle)[0])
                finally:
                    win.close(handle)

    def test_atomic_replace_preserves_later_user_settings_and_removes_only_owned_hooks(self):
        configure("install", self.settings, self.project)
        data = json.loads(self.settings.read_text())
        data["later_user_edit"] = 123
        self.settings.write_text(json.dumps(data))
        self.assertEqual(configure("uninstall", self.settings, self.project)["status"], "uninstalled")
        self.assertEqual(json.loads(self.settings.read_text()), {"later_user_edit": 123})

    def test_hardlinked_config_is_refused_without_changes(self):
        self.settings.parent.mkdir()
        target = self.base / "original.json"
        target.write_text('{}')
        os.link(target, self.settings)
        with self.assertRaises((OSError, ValueError)):
            configure("install", self.settings, self.project)
        self.assertEqual(target.read_text(), '{}')

    def test_junction_configuration_parent_is_refused(self):
        target = self.base / "target"
        target.mkdir()
        self.junction(self.settings.parent, target)
        with self.assertRaises(OSError):
            configure("install", self.settings, self.project)
        self.assertEqual(list(target.iterdir()), [])

    def test_foreign_write_acl_is_refused(self):
        from protection_agency import windows_files as win
        self.settings.parent.mkdir()
        self.settings.write_text('{}')
        tool = Path(os.environ["SystemRoot"]) / "System32/icacls.exe"
        result = subprocess.run([str(tool), str(self.settings), "/grant", "*S-1-1-0:(W)"], capture_output=True)
        self.assertEqual(result.returncode, 0)
        with self.assertRaises(ValueError):
            snapshot(self.settings)
        self.assertEqual(self.settings.read_text(), '{}')

    def test_snapshot_drift_refuses_edit(self):
        configure("install", self.settings, self.project)
        expected = snapshot(self.settings)
        self.settings.write_text('{"changed":true}')
        result = configure("install", self.settings, self.project, expected_snapshot=expected)
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(self.settings.read_text(), '{"changed":true}')

    def test_lock_content_and_active_lock_prevent_replacement(self):
        from protection_agency import windows_files as win
        import ctypes as C
        configure("install", self.settings, self.project)
        lock_name = '.settings.json.protection-agency.lock'
        with win.pin_directory(self.settings.parent) as parent:
            lock = win.open_relative(parent, lock_name, 0xC0000000, share=3)
            overlap = win.Overlapped()
            try:
                win.checked(win.lock_file(lock, 3, 0, 1, 0, C.byref(overlap)))
                result = configure("install", self.settings, self.project, online=True)
                self.assertEqual(result["status"], "conflict")
            finally:
                win.unlock_file(lock, 0, 1, 0, C.byref(overlap))
                win.close(lock)
        (self.settings.parent / lock_name).write_text('unrelated lock')
        with self.assertRaises(ValueError):
            configure("install", self.settings, self.project, online=True)

    def test_pinned_directory_cannot_be_renamed_during_use(self):
        from protection_agency import windows_files as win
        with win.pin_directory(self.project):
            with self.assertRaises(OSError):
                self.project.rename(self.base / "moved")

    def test_codex_cmd_and_powershell_relay_preserve_denial_with_special_paths(self):
        from protection_agency.agents import codex_command
        folder = self.base / "script space & ' ü"
        folder.mkdir()
        # The real trusted launcher stays outside the inspected root. Using a
        # source path with metacharacters verifies that only literal argv runs.
        guard = folder / "guard.py"
        guard.write_text("import runpy\nrunpy.run_path(" + repr(str(SOURCE / 'guard.py')) + ", run_name='__main__')\n")
        command = codex_command(Path(sys.executable), guard, False)
        event = json.dumps({"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":str(self.project),
                            "tool_input":{"command":"npm install cdeops@13.5.31"}})
        system = Path(os.environ["SystemRoot"]) / "System32"
        cases = [[str(system / "cmd.exe"), "/d", "/c", command],
                 [str(system / "WindowsPowerShell/v1.0/powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", command]]
        for argv in cases:
            result = subprocess.run(argv, input=event, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_codex_and_claude_profiles_pass_local_probe_on_windows(self):
        for agent in ("codex", "claude"):
            settings = self.base / agent / "hooks.json"
            configure("install", settings, self.project, agent=agent)
            result = inspect_configuration(settings, self.project, agent=agent, probe=True)
            self.assertEqual(result["probe"], "passed")
            self.assertEqual(result["live_client_enforcement"], "not_verified")

    def test_startup_gate_launches_native_python_with_literal_arguments(self):
        marker = self.base / "marker.json"
        script = self.base / "client.py"
        script.write_text('import sys,json\nfrom pathlib import Path\nPath(' + repr(str(marker)) + ').write_text(json.dumps(sys.argv[1:]))\n')
        output = io.StringIO()
        status = open_client(self.project, client=sys.executable, online=True, client_args=['-I', str(script), 'literal & %whoami%'], output_stream=output)
        self.assertEqual(status, 0, output.getvalue())
        self.assertEqual(json.loads(marker.read_text()), ['literal & %whoami%'])

    def test_batch_client_is_refused_even_with_shell_false(self):
        script = self.base / "untrusted.cmd"
        script.write_text('@echo should-not-run')
        status = open_client(self.project, client=script, online=True, output_stream=io.StringIO())
        self.assertEqual(status, 3)

    def test_startup_dry_run_and_high_finding_do_not_start_client(self):
        marker = self.base / "marker"
        script = self.base / "client.py"
        script.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()')
        self.assertEqual(open_client(self.project, client=sys.executable, online=True, dry_run=True,
            client_args=['-I', str(script)], output_stream=io.StringIO()), 0)
        self.assertFalse(marker.exists())
        (self.project / 'package.json').write_text('{"dependencies":{"cdeops":"13.5.31"}}')
        self.assertEqual(open_client(self.project, client=sys.executable, online=True,
            client_args=['-I', str(script)], output_stream=io.StringIO()), 1)
        self.assertFalse(marker.exists())

    def test_guided_setup_uses_powershell_function_without_profile_edits(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        output = io.StringIO()
        status = setup(self.project, agent='claude', settings=self.settings, online=False,
                       input_stream=Terminal('yes\n'), output_stream=output)
        self.assertEqual(status, 0, output.getvalue())
        self.assertIn('function agency {', output.getvalue())
        self.assertNotIn('alias agency=', output.getvalue())
