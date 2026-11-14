"""User-invoked setup, inert demonstration, and a readable client entry point."""
import errno
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

from .doctor import diagnose
from .integration import _load, _locations, configure, inspect_configuration, probe_protocol
from .launcher import clean_environment, launch
from .models import label
from .presentation import doctor_result, launch_receipt, setup_result
from .agents import get_agent, default_settings
from .filesystem import normalize_root


def error_hint(error):
    """Explain known failures without echoing arbitrary exception/target contents."""
    hints = {
        "choose an absolute user settings file outside the project": "Choose an existing project and absolute user settings outside it. Run setup from your project folder, with the scanner in its separate trusted directory.",
        "use a trusted external Python and source installation": "Keep the Python interpreter and complete scanner checkout outside the project you inspect.",
        "configuration must be user-owned and not writable by other users": "Settings and their directory must be owned by you and not writable by other users. Inspect ownership/permissions; do not loosen them to force setup.",
        "configuration must be a bounded regular file with one link": "Use a regular settings file with one hard link, at most 1 MiB. Inspect the file without overwriting it.",
        "duplicate JSON configuration key": "Settings contain duplicate JSON keys. Resolve that ambiguity while preserving your existing settings, then retry.",
        "JSON configuration exceeds nesting budget": "Settings exceed the supported nesting budget. Inspect them before retrying.",
        "global configuration points inside the untrusted project or uses a relative path": "A global configuration environment path points into the project or is relative. Use your trusted external user profile.",
        "configuration grants write access to another principal": "The Windows settings ACL allows another principal to write. Inspect its access controls before retrying; do not broaden access to force setup.",
        "Windows secure access currently supports NTFS only": "Native Windows checks currently require local NTFS. Network shares and other filesystems have not been enabled.",
        "Windows secure access requires a local fixed drive": "Select a project on a local fixed NTFS drive. Network and removable drives are outside this backend's supported scope.",
    }
    if isinstance(error, (ValueError, OSError)) and str(error) in hints:
        return hints[str(error)]
    if isinstance(error, json.JSONDecodeError):
        return "Settings JSON could not be parsed. Inspect it without discarding existing settings; original bytes have not been replaced by a parse failure."
    if isinstance(error, OSError):
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            return "A path is indirect, symlinked, or not a directory. Choose a direct trusted configuration path; setup refuses symlinks."
        if error.errno in {errno.EACCES, errno.EPERM}:
            return "A required path could not be accessed. Inspect ownership/permissions; do not run setup as administrator to bypass the check."
        if error.errno == errno.ENOENT:
            return "A required project, interpreter, or scanner path was missing. Select an existing project and keep the trusted checkout complete."
    return "Check the project path, trusted source/interpreter, and settings format/permissions. See docs/GETTING-STARTED.md for common stops."


def settings_path(explicit=None, agent="claude"):
    return default_settings(agent, explicit)


def _yes(source, output, prompt):
    output.write(prompt + " [y/N] ")
    output.flush()
    return source.readline(32).strip().lower() in {"y", "yes"}


def _shell_line(argv):
    if sum(map(len, argv)) > 4096 or any(not char.isprintable() for arg in argv for char in arg):
        return "(Path cannot be displayed as a shell command; use explicit trusted paths.)"
    return ("& " + " ".join("'" + arg.replace("'", "''") + "'" for arg in argv)) if os.name == "nt" else shlex.join(argv)


def setup(root, *, settings=None, online=None, dry_run=False, input_stream=None, output_stream=None, agent="claude"):
    source = sys.stdin if input_stream is None else input_stream
    output = sys.stdout if output_stream is None else output_stream
    if agent is None:
        if dry_run or not source.isatty():
            output.write("Choose --agent codex or --agent claude. Preview example: setup --agent codex --dry-run\n")
            return 2
        output.write("Choose your agent [codex/claude]: ")
        output.flush()
        agent = source.readline(32).strip().lower()
        if agent not in {"codex", "claude"}:
            output.write("No agent selected. No settings were changed.\n")
            return 2
    adapter = get_agent(agent)
    if not sys.flags.isolated:
        output.write("Setup needs isolated Python. Run: python3 -I /trusted/protection-agency/guard.py setup /path/to/project\n")
        return 3
    project = normalize_root(root)
    settings, project, python, launcher = _locations(settings_path(settings, agent), project)
    clean_environment(project, os.environ)
    output.write("Protection Agency: set up " + adapter.label + " command checks\n")
    output.write("Project: " + label(str(project), 1000) + "\nUser settings: " + label(str(settings), 1000) + "\n")
    output.write("Adds a project-start scan and checks for the selected client's shell tool.\n")
    output.write("Contract version reference: " + adapter.version_reference + ". Installed version and native enforcement are not verified here.\n")
    if agent == "codex":
        output.write("Codex strict shell adapter: commands needing review are denied because native 'ask' is unsupported. Hook errors/timeouts may continue in the client. Review and trust hooks in native /hooks; keep sandboxing and permissions enabled.\n")
    if not dry_run and not source.isatty():
        output.write("Interactive setup needs a terminal. Use --dry-run for a preview, or the explicit install-hooks command for automation. No settings were changed.\n")
        return 2
    if not dry_run:
        checks = diagnose(project)
        if checks["status"] == "failed":
            output.write(doctor_result(checks) + "\nSetup stopped before changing settings.\n")
            return 3
    _, snapshot = _load(settings)
    output.write("Online checks send eligible public package names/versions to OSV; no source or credentials. Keep confidential inventories offline.\n")
    if online is None:
        online = False if dry_run else _yes(source, output, "Enable online vulnerability checks for the installed hooks?")
    output.write("Installed hook advisory mode: " + ("online" if online else "offline; current vulnerability advisories will not be checked") + ".\n")
    preview = configure("install", settings, project, online=online, dry_run=True, expected_snapshot=snapshot, agent=agent)
    output.write(setup_result(preview) + "\n")
    if preview["status"] not in {"would_install", "already_installed"}:
        return 2
    output.write("Preserves unrelated settings; edits normalize JSON comments/formatting. Existing bytes get a private backup.\n")
    output.write("Setup does not scan or approve the whole project, start a client, or change native permissions.\n")
    if dry_run:
        output.write("Preview complete. No files or directories were created.\n")
        return 0
    if preview["status"] == "would_install":
        if not _yes(source, output, "Install these two hook groups in the user settings shown above?"):
            output.write("Setup cancelled. No settings were changed.\n")
            return 2
        result = configure("install", settings, project, online=online, expected_snapshot=snapshot, agent=agent)
        output.write(setup_result(result) + "\n")
        if result["status"] not in {"installed", "already_installed"}:
            return 2
    inspection = inspect_configuration(settings, project, probe=True, agent=agent)
    output.write("Hook configuration: " + inspection["status"] + "\nTrusted hook response test: " + inspection["probe"] + "\n")
    if inspection["status"] != "configured" or inspection["probe"] != "passed":
        output.write("Setup could not verify the local hook response. Inspect with doctor --root PROJECT --settings FILE --probe-hooks --human before relying on it.\n")
        return 2
    output.write("Local configuration and response tests passed. Native client enforcement remains unverified.\n")
    command = _shell_line([str(python), "-I", str(launcher)])
    if not command.startswith("("):
        if os.name == "nt":
            output.write("\nOptional function for this PowerShell terminal (no profile is edited):\n")
            output.write("function agency { " + command + " @args }\n")
        else:
            output.write("\nOptional shortcut for this terminal (bash/zsh; no shell startup file is edited):\n")
            output.write("alias agency=" + shlex.quote(command) + "\n")
    output.write("Next project check: " + _shell_line(["agency", "check", str(project), *(["--online"] if online else [])]) + "\n")
    if online:
        output.write("Check before starting your agent: " + _shell_line(["agency", "open", str(project), "--agent", agent, "--online"]) + "\n")
    else:
        output.write("The startup gate needs completed online advisory checks; offline mode will stop before client execution.\n")
    output.write("Restart the selected client, inspect /hooks, and confirm that it loads/trusts this user profile. Keep its sandbox and permissions enabled.\n")
    return 0


def demo(*, agent="claude"):
    """Use a disposable empty project; example commands are hook input text only."""
    try:
        with tempfile.TemporaryDirectory(prefix="protection-agency-demo-") as temporary:
            base = Path(temporary).resolve()
            project = base / "empty-project"
            project.mkdir()
            _, project, python, launcher = _locations(base / "unused-settings.json", project)
            checks = probe_protocol(project, python, launcher, agent=agent)
    except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
        checks = [{"check": "trusted_hook_protocol", "status": "failed"}]
    return {"status": "passed" if len(checks) == 3 and all(c["status"] == "passed" for c in checks) else "failed",
            "checks": checks, "project_commands_executed": False, "network_requests": False,
            "live_client_enforcement": "not_verified", "agent": agent}


def demo_text(result):
    if result["status"] != "passed":
        return "The trusted hook demonstration failed. No example command was executed; inspect doctor before using the integration."
    return ("Protection Agency demo\n"
            "Command text: npm install cdeops@13.5.31\n"
            "BLOCKED by the guard: this exact release is listed as malicious in the bundled indicators.\n"
            "A simple read kept native permissions in control; malformed hook input failed.\n"
            "No example commands were executed. Nothing was installed or downloaded.\n"
            "This tested the selected adapter's responses, not a running native client. Native enforcement remains unverified.")


def open_client(root, *, client=None, online=False, review=False, dry_run=False, client_args=(), output_stream=None, agent="claude"):
    output = sys.stderr if output_stream is None else output_stream
    project = normalize_root(root)
    if client is None:
        if agent is None:
            output.write("Choose --agent codex or --agent claude (or an explicit --client path). No client was started.\n")
            return 2
        adapter = get_agent(agent)
        environment, _, _ = clean_environment(project, os.environ)
        if os.name == "nt":
            client = next((str(Path(entry) / (agent + ".exe")) for entry in environment["PATH"].split(os.pathsep)
                           if (Path(entry) / (agent + ".exe")).is_file()), None)
        else:
            client = shutil.which(agent, path=environment["PATH"])
        if client is None:
            output.write(adapter.label + " was not found on the trusted PATH. Supply --client with an absolute trusted executable path. No client was started.\n")
            return 3
    else:
        client = str(client)
    if not Path(client).is_absolute():
        output.write("--client must name an absolute trusted executable outside the project. No client was started.\n")
        return 3
    if dry_run:
        output.write("Preview only: the selected client will not be started.\n")
    output.write("Checking before starting " + label(Path(client).name) + "...\n")
    return launch(project, [client, *client_args], online=online, review=review, dry_run=dry_run,
                  output_stream=output, receipt_formatter=launch_receipt)
