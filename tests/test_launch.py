"""Launch-gate tests run an inert external marker-writing client, never malware."""
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from protection_agency.scanner import Scanner

PROJECT = Path(__file__).resolve().parents[1]


class ReviewTerminal:
    def __init__(self, output, callback=lambda: None, accept=True):
        self.output, self.callback, self.accept = output, callback, accept
        self.called = False

    def isatty(self):
        return True

    def readline(self, size=-1):
        self.called = True
        match = re.search(r"Review challenge: (APPROVE [0-9a-f]{12})", self.output.getvalue())
        if not match:
            raise AssertionError("review challenge missing")
        self.callback()
        return (match[1] if self.accept else "decline") + "\n"


@unittest.skipIf(os.name == "nt", "POSIX launch contract; native Windows parity is in test_windows")
class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pa-launch-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "project"
        self.root.mkdir()
        (self.root / ".git").mkdir()
        (self.root / ".git/config").write_text("[core]\nrepositoryformatversion = 0\n")
        (self.root / "app.js").write_text("const answer = 42;\n")
        self.marker = self.base / "client-started.json"
        self.agent = self.base / "trusted-client.py"
        self.agent.write_text('''import json, os, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "cwd": str(pathlib.Path.cwd()), "args": sys.argv[2:],
    "node_options": os.environ.get("NODE_OPTIONS"),
    "pythonpath": os.environ.get("PYTHONPATH"),
    "path": os.environ.get("PATH"), "auth": os.environ.get("PA_TEST_AUTH")
}))
raise SystemExit(int(os.environ.get("PA_TEST_EXIT", "0")))
''')
        self.output = io.StringIO()

    @property
    def command(self):
        return [sys.executable, "-I", str(self.agent), str(self.marker)]

    def cli(self, *options, env=None, command=None):
        result = subprocess.run([sys.executable, "-I", str(PROJECT / "guard.py"), "launch", *options,
            str(self.root), "--", *(command or self.command)], env=env, capture_output=True, text=True, timeout=10)
        self.assertIn('"execution"', result.stdout if "--dry-run" in options else result.stderr)
        return result

    def api(self, command=None, **kwargs):
        from protection_agency.launcher import launch
        return launch(self.root, command or self.command, online=True, output_stream=self.output, **kwargs)

    def startup(self):
        folder = self.root / ".claude"
        folder.mkdir(exist_ok=True)
        (folder / "settings.json").write_text(json.dumps({"hooks": {"SessionStart": [
            {"hooks": [{"type": "command", "command": "echo inert-startup"}]}]}}))

    def test_clean_project_launches_external_client_in_project(self):
        result = self.cli("--online")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.marker.read_text())["cwd"], str(self.root))

    def test_review_blocks_startup_before_client_process_exists(self):
        self.startup()
        result = self.cli("--online")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_high_priority_finding_cannot_be_overridden_by_review(self):
        (self.root / "app.js").write_text("eval(atob('inert-example'))")
        result = self.cli("--online", "--review")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_offline_advisories_block_even_with_review(self):
        result = self.cli("--review")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_incomplete_inventory_blocks_even_with_review(self):
        (self.root / "package.json").write_text('{"dependencies":{"missing":"^1.0.0"}}')
        result = self.cli("--online", "--review")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_dry_run_never_launches(self):
        result = self.cli("--online", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["execution"], "not_started")
        self.assertFalse(self.marker.exists())

    def test_interactive_review_is_bound_to_rechecked_content(self):
        self.startup()
        terminal = ReviewTerminal(self.output)
        self.assertEqual(self.api(review=True, input_stream=terminal), 0)
        self.assertTrue(terminal.called)
        self.assertTrue(self.marker.exists())

    def test_non_terminal_review_cannot_approve(self):
        self.startup()
        self.assertEqual(self.api(review=True, input_stream=io.StringIO("APPROVE any\n")), 2)
        self.assertFalse(self.marker.exists())

    def test_declined_review_does_not_launch(self):
        self.startup()
        terminal = ReviewTerminal(self.output, accept=False)
        self.assertEqual(self.api(review=True, input_stream=terminal), 2)
        self.assertFalse(self.marker.exists())

    def test_same_size_same_mtime_change_during_review_stops_launch(self):
        self.startup()
        path = self.root / "app.js"
        before = path.stat()
        def change():
            path.write_text("const answer = 43;\n")
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(self.api(review=True, input_stream=ReviewTerminal(self.output, change)), 2)
        self.assertFalse(self.marker.exists())

    def test_new_startup_file_during_review_stops_launch(self):
        (self.root / "README.md").write_text("Documentation example: eval(atob('inert'))")
        self.assertEqual(self.api(review=True, input_stream=ReviewTerminal(self.output, self.startup)), 2)
        self.assertFalse(self.marker.exists())

    def test_scanner_failure_never_starts_client(self):
        with patch("protection_agency.launcher.Scanner.scan", side_effect=RuntimeError("inert fault")):
            self.assertEqual(self.api(), 3)
        self.assertFalse(self.marker.exists())

    def test_agent_inside_project_is_rejected(self):
        client = self.root / "client"
        client.write_text("#!/bin/sh\nexit 0\n")
        client.chmod(0o755)
        result = self.cli("--online", command=[str(client)])
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_relative_executable_and_shell_lookup_are_rejected(self):
        result = self.cli("--online", command=["python3", "-I", str(self.agent), str(self.marker)])
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_loader_environment_and_project_path_are_removed(self):
        env = dict(os.environ, NODE_OPTIONS="--require ./inert-loader.js", PYTHONPATH=str(self.root), PA_TEST_AUTH="inert-auth")
        env["PATH"] = os.pathsep.join([".", str(self.root), env.get("PATH", os.defpath)])
        result = self.cli("--online", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(self.marker.read_text())
        self.assertIsNone(data["node_options"])
        self.assertIsNone(data["pythonpath"])
        self.assertNotIn(".", data["path"].split(os.pathsep))
        self.assertNotIn(str(self.root), data["path"].split(os.pathsep))
        self.assertEqual(data["auth"], "inert-auth")
        self.assertNotIn("inert-auth", result.stderr)

    def test_child_exit_status_and_literal_arguments_are_preserved(self):
        env = dict(os.environ, PA_TEST_EXIT="7")
        literal = "; touch SHOULD_NOT_RUN"
        result = self.cli("--online", env=env, command=[*self.command, literal])
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(json.loads(self.marker.read_text())["args"], [literal])
        self.assertFalse((self.root / "SHOULD_NOT_RUN").exists())

    def test_active_git_helper_is_reviewed_before_launch(self):
        (self.root / ".git/config").write_text('[core]\nfsmonitor = echo inert-helper\n')
        result = self.cli("--online")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_git_worktree_indirection_is_incomplete(self):
        (self.root / ".git/config").unlink()
        (self.root / ".git").rmdir()
        (self.root / ".git").write_text("gitdir: ../outside-git")
        result = self.cli("--online", "--review")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_snapshot_changes_with_selected_content(self):
        scanner = Scanner(self.root)
        first = scanner.scan().snapshot_id
        (self.root / "app.js").write_text("const answer = 43;\n")
        second = scanner.scan().snapshot_id
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first, second)

    def test_replaced_project_directory_cannot_reuse_review(self):
        self.startup()
        def replace():
            previous = self.base / "previous-project"
            self.root.rename(previous)
            shutil.copytree(previous, self.root)
        self.assertEqual(self.api(review=True, input_stream=ReviewTerminal(self.output, replace)), 2)
        self.assertFalse(self.marker.exists())

    def test_changed_trusted_executable_is_not_launched(self):
        self.startup()
        executable = self.base / "trusted-executable"
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        def change():
            executable.write_text("#!/bin/sh\nexit 1\n# changed\n")
        terminal = ReviewTerminal(self.output, change)
        self.assertEqual(self.api(command=[str(executable)], review=True, input_stream=terminal), 2)
        self.assertFalse(self.marker.exists())

    def test_git_hook_mode_change_during_review_stops_launch(self):
        self.startup()
        hooks = self.root / ".git/hooks"
        hooks.mkdir()
        hook = hooks / "pre-commit"
        hook.write_text("#!/bin/sh\nexit 0\n")
        hook.chmod(0o644)
        terminal = ReviewTerminal(self.output, lambda: hook.chmod(0o755))
        self.assertEqual(self.api(review=True, input_stream=terminal), 2)
        self.assertFalse(self.marker.exists())

    def test_executable_git_hook_blocks_default_launch(self):
        hooks = self.root / ".git/hooks"
        hooks.mkdir()
        hook = hooks / "post-checkout"
        hook.write_text("#!/bin/sh\nexit 0\n")
        hook.chmod(0o755)
        result = self.cli("--online")
        self.assertEqual(result.returncode, 2)
        self.assertIn("PA501", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_symlinked_git_hook_directory_is_not_followed(self):
        outside = self.base / "outside-hooks"
        outside.mkdir()
        (outside / "pre-commit").write_text("inert-outside-content")
        (self.root / ".git/hooks").symlink_to(outside, target_is_directory=True)
        result = self.cli("--online", "--review")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("inert-outside-content", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_git_config_includes_are_incomplete(self):
        (self.root / ".git/config").write_text('[include]\npath = ../outside-config\n')
        result = self.cli("--online", "--review")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.marker.exists())

    def test_ancestor_agent_configuration_is_outside_scope(self):
        folder = self.base / ".claude"
        folder.mkdir()
        (folder / "settings.json").write_text('{"hooks":{}}')
        result = self.cli("--online", "--review")
        self.assertEqual(result.returncode, 2)
        self.assertIn("above the selected root", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_advisory_failure_cannot_be_reviewed_away(self):
        from protection_agency.models import Report
        report = Report("standard", True, advisories="incomplete", snapshot_id="a" * 64)
        terminal = ReviewTerminal(self.output)
        with patch("protection_agency.launcher.Scanner.scan", return_value=report):
            self.assertEqual(self.api(review=True, input_stream=terminal), 2)
        self.assertFalse(terminal.called)
        self.assertFalse(self.marker.exists())

    def test_large_review_cannot_be_approved_from_a_truncated_report(self):
        for index in range(51):
            (self.root / f"README_{index}.md").write_text("Inert example: eval(atob('example'))")
        terminal = ReviewTerminal(self.output)
        self.assertEqual(self.api(review=True, input_stream=terminal), 2)
        self.assertFalse(terminal.called)
        self.assertFalse(self.marker.exists())

    def test_non_isolated_python_cannot_launch(self):
        result = subprocess.run([sys.executable, str(PROJECT / "guard.py"), "launch", "--online",
            str(self.root), "--", *self.command], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 3)
        self.assertFalse(self.marker.exists())

    def test_scanner_inside_selected_root_cannot_launch(self):
        from protection_agency import launcher
        with patch.object(launcher, "__file__", str(self.root / "untrusted-scanner.py")):
            self.assertEqual(self.api(), 3)
        self.assertFalse(self.marker.exists())

    def test_expired_review_cannot_start_client(self):
        self.startup()
        terminal = ReviewTerminal(self.output)
        with patch("protection_agency.launcher.monotonic", side_effect=[0, 301]):
            self.assertEqual(self.api(review=True, input_stream=terminal), 2)
        self.assertIn("Preflight expired", self.output.getvalue())
        self.assertFalse(self.marker.exists())

    def test_expired_final_recheck_cannot_start_client(self):
        with patch("protection_agency.launcher.monotonic", side_effect=[0, 1, 301]):
            self.assertEqual(self.api(), 2)
        self.assertFalse(self.marker.exists())

    def test_launch_help_does_not_require_a_command(self):
        for flag in ("-h", "--help"):
            result = subprocess.run([sys.executable, "-I", str(PROJECT / "guard.py"), "launch", flag],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--dry-run", result.stdout)

    def test_missing_separator_or_client_fails_without_launching(self):
        for args in ([str(self.root), *self.command], [str(self.root), "--"]):
            result = subprocess.run([sys.executable, "-I", str(PROJECT / "guard.py"), "launch", *args],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(self.marker.exists())

    def test_git_environment_helpers_are_removed_and_auth_is_preserved(self):
        from protection_agency.launcher import clean_environment
        environ = {"PATH": os.defpath, "GIT_SSH_COMMAND": "inert-helper", "HTTPS_PROXY": "inert-proxy",
                   "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "http.extraHeader",
                   "GIT_CONFIG_VALUE_0": "inert-auth-secret", "GIT_CONFIG_KEY_1": "core.fsmonitor",
                   "GIT_CONFIG_VALUE_1": "inert-helper-command"}
        result, removed, _ = clean_environment(self.root, environ)
        self.assertNotIn("GIT_SSH_COMMAND", result)
        self.assertEqual(result["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(result["GIT_CONFIG_VALUE_0"], "inert-auth-secret")
        self.assertEqual(result["HTTPS_PROXY"], "inert-proxy")
        self.assertNotIn("inert-auth-secret", json.dumps(removed))
        self.assertNotIn("inert-helper-command", json.dumps(removed))

    def test_exported_shell_functions_and_loader_audit_are_removed(self):
        from protection_agency.launcher import clean_environment
        result, removed, _ = clean_environment(self.root, {
            "PATH": os.defpath, "BASH_FUNC_node%%": "inert-function-definition",
            "LD_AUDIT": "inert-library-path", "PYTHONUSERBASE": str(self.root), "PYTHONWARNINGS": "inert-warning-module"})
        self.assertTrue(all(key not in result for key in ("BASH_FUNC_node%%", "LD_AUDIT", "PYTHONUSERBASE", "PYTHONWARNINGS")))
        self.assertNotIn("inert-function-definition", json.dumps(removed))

    def test_entirely_project_relative_path_cannot_launch(self):
        env = dict(os.environ, PATH=os.pathsep.join([".", str(self.root)]))
        result = self.cli("--online", env=env)
        self.assertEqual(result.returncode, 3)
        self.assertFalse(self.marker.exists())

    def test_interrupted_review_does_not_start_client(self):
        self.startup()
        terminal = ReviewTerminal(self.output)
        def interrupt(size=-1):
            raise KeyboardInterrupt()
        terminal.readline = interrupt
        self.assertEqual(self.api(review=True, input_stream=terminal), 130)
        self.assertFalse(self.marker.exists())

    def test_duplicate_git_options_are_incomplete(self):
        (self.root / ".git/config").write_text('[remote "origin"]\nurl = ext::inert-example\nurl = https://example.invalid/repo\n')
        result = self.cli("--online", "--review")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.marker.exists())

    def test_indirect_shared_git_config_is_incomplete(self):
        (self.root / ".git/commondir").write_text("../../outside-git")
        result = self.cli("--online", "--review")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.marker.exists())

    def test_per_worktree_git_config_is_incomplete(self):
        (self.root / ".git/config.worktree").write_text('[core]\nfsmonitor = echo inert-helper\n')
        result = self.cli("--online", "--review")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.marker.exists())

    def test_global_config_override_cannot_point_into_project(self):
        for name in ("HOME", "XDG_CONFIG_HOME", "CLAUDE_CONFIG_DIR", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
            result = self.cli("--online", env=dict(os.environ, **{name: str(self.root / "untrusted-config")}))
            self.assertEqual(result.returncode, 3, name)
            self.assertFalse(self.marker.exists())

    def test_custom_git_hook_path_is_incomplete(self):
        (self.root / ".git/config").write_text('[core]\nhooksPath = ../outside-hooks\n')
        result = self.cli("--online", "--review")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.marker.exists())

    def test_submodule_custom_update_is_a_review_surface(self):
        (self.root / ".git/config").write_text('[submodule "inert"]\nupdate = !echo inert-helper\n')
        result = self.cli("--online")
        self.assertEqual(result.returncode, 2)
        self.assertIn("PA500", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_real_terminal_review_starts_client_only_after_challenge(self):
        import pty
        import select
        self.startup()
        master, slave = pty.openpty()
        process = None
        try:
            process = subprocess.Popen([sys.executable, "-I", str(PROJECT / "guard.py"), "launch", "--online", "--review",
                str(self.root), "--", *self.command], stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            observed = b""
            challenge = None
            # Read unbuffered bytes to avoid losing readiness to a buffered reader.
            for _ in range(100000):
                ready, _, _ = select.select([process.stderr], [], [], 5)
                if not ready:
                    self.fail("terminal challenge timed out")
                chunk = os.read(process.stderr.fileno(), 1)
                if not chunk:
                    self.fail("launcher ended before terminal review")
                observed += chunk
                match = re.search(rb"Review challenge: (APPROVE [0-9a-f]{12})\n", observed)
                if match:
                    challenge = match[1]
                    break
            self.assertIsNotNone(challenge)
            self.assertFalse(self.marker.exists())
            os.write(master, challenge + b"\n")
            _, remaining = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, (observed + remaining).decode())
            self.assertTrue(self.marker.exists())
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            os.close(master)
            os.close(slave)
