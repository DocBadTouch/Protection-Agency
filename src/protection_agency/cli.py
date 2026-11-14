import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .policy import check_command
from .scanner import Scanner


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="protection-agency", description="Your agent needs an agency. Screen projects and gate an explicitly selected client launch; never a safety guarantee.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="subcommand", required=True)
    adapters = commands.add_parser("agents", help="Show adapter/platform capabilities separately from native verification")
    adapters.add_argument("--json", action="store_true")
    friendly = commands.add_parser("check", help="Check a project and show readable findings and next steps")
    friendly.add_argument("root", type=Path, nargs="?", default=Path("."))
    friendly.add_argument("--level", choices=["quick", "standard", "deep"], default="standard")
    friendly.add_argument("--online", action="store_true")
    friendly.add_argument("--full", action="store_true")
    friendly.add_argument("--json", action="store_true", help="Return machine-readable output")
    demonstration = commands.add_parser("demo", help="Demonstrate trusted hook responses without executing example commands")
    demonstration.add_argument("--json", action="store_true")
    demonstration.add_argument("--agent", choices=["codex", "claude"], default="claude")
    guided = commands.add_parser("setup", help="Guided Claude user-hook setup, preview, and local response test")
    guided.add_argument("root", type=Path, nargs="?", default=Path("."))
    guided.add_argument("--settings", type=Path)
    guided.add_argument("--agent", choices=["codex", "claude"], help="Select an adapter; interactive setup asks if omitted")
    mode = guided.add_mutually_exclusive_group()
    mode.add_argument("--online", dest="online", action="store_true")
    mode.add_argument("--offline", dest="online", action="store_false")
    guided.set_defaults(online=None)
    guided.add_argument("--dry-run", action="store_true")
    opening = commands.add_parser("open", help="Check first, then open a trusted Claude executable; no sandbox provided")
    opening.add_argument("root", type=Path, nargs="?", default=Path("."))
    opening.add_argument("--agent", choices=["codex", "claude"], help="Select which client to discover")
    opening.add_argument("--client", type=Path, help="Absolute trusted client; default finds claude outside the project on the sanitized PATH")
    opening.add_argument("--online", action="store_true")
    opening.add_argument("--review", action="store_true")
    opening.add_argument("--dry-run", action="store_true")
    scan = commands.add_parser("scan", help="Screen a project without executing its code")
    scan.add_argument("root", type=Path)
    scan.add_argument("--level", choices=["quick", "standard", "deep"], default="standard")
    scan.add_argument("--online", action="store_true", help="Opt in to sending eligible package names/versions to OSV")
    scan.add_argument("--full", action="store_true", help="Include all finding details")
    server = commands.add_parser("serve", help="Start a workspace-scoped MCP stdio server")
    server.add_argument("--root", type=Path, required=True)
    server.add_argument("--online", action="store_true")
    hook = commands.add_parser("hook", help="Read a Claude SessionStart or PreToolUse event on stdin")
    hook.add_argument("--online", action="store_true")
    hook.add_argument("--agent", choices=["codex", "claude"], default="claude")
    check = commands.add_parser("check-command", help="Classify a command as text; never execute it")
    check.add_argument("command")
    dependency = commands.add_parser("check-dependency", help="Check a proposed release without installing or resolving it")
    dependency.add_argument("ecosystem", choices=["npm", "PyPI"])
    dependency.add_argument("name")
    dependency.add_argument("version", nargs="?", default="")
    dependency.add_argument("--registry", help="Explicit registry provenance; unknown/private registries are not queried")
    dependency.add_argument("--online", action="store_true")
    doctor = commands.add_parser("doctor", help="Run offline scanner diagnostics; does not certify live agent enforcement")
    doctor.add_argument("--root", type=Path)
    doctor.add_argument("--agent", choices=["codex", "claude"], default="claude")
    doctor.add_argument("--settings", type=Path, help="Inspect Claude user settings outside the project")
    doctor.add_argument("--probe-hooks", action="store_true", help="Exercise only the reconstructed trusted guard hook; not the native client")
    doctor.add_argument("--human", action="store_true", help="Show a readable diagnostic summary")
    for action in ("install-hooks", "uninstall-hooks"):
        setup = commands.add_parser(action, help="Manage only Protection Agency's Claude user hooks with private backups")
        setup.add_argument("--project", type=Path, required=True)
        setup.add_argument("--settings", type=Path)
        setup.add_argument("--agent", choices=["codex", "claude"], default="claude")
        setup.add_argument("--dry-run", action="store_true")
        setup.add_argument("--human", action="store_true")
        if action == "install-hooks":
            setup.add_argument("--online", action="store_true")
    launch_parser = commands.add_parser("launch", help="Inspect before launching a trusted external client; does not provide a sandbox")
    launch_parser.add_argument("root", type=Path)
    launch_parser.add_argument("--online", action="store_true")
    launch_parser.add_argument("--review", action="store_true", help="Permit explicit terminal review of lower-priority findings when coverage is complete")
    launch_parser.add_argument("--dry-run", action="store_true", help="Print preflight only; never start a client")
    argv = list(sys.argv[1:] if argv is None else argv)
    launch_command = []
    if argv[:1] == ["open"] and "--" in argv:
        index = argv.index("--")
        launch_command, argv = argv[index + 1:], argv[:index]
    before_separator = argv[:argv.index("--")] if "--" in argv else argv
    if argv[:1] == ["launch"] and not {"--help", "-h"}.intersection(before_separator):
        if "--" not in argv:
            parser.error("launch requires -- followed by an absolute client executable and its arguments")
        index = argv.index("--")
        launch_command, argv = argv[index + 1:], argv[:index]
        if not launch_command:
            parser.error("launch requires a client executable after --")
    args = parser.parse_args(argv)
    if args.subcommand == "doctor" and ((args.settings is not None and args.root is None)
                                       or args.probe_hooks and args.settings is None):
        parser.error("doctor configuration checks require --root and --settings; --probe-hooks also requires both")
    try:
        if args.subcommand == "agents":
            from .agents import capabilities
            result = capabilities()
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print("Protection Agency adapters (native enforcement unverified)")
                for agent in result["agents"]:
                    print(agent["label"] + ": shell hook + shared read-only MCP; hook failures: " + agent["hook_error_behavior"])
                print("Other MCP-compatible clients can use advisory tools; MCP alone does not intercept their execution.")
                print("Filesystem backend: " + result["scan_and_mcp"])
            return 0
        if args.subcommand == "setup":
            from .onboarding import setup as guided_setup
            return guided_setup(args.root, settings=args.settings, online=args.online, dry_run=args.dry_run, agent=args.agent)
        if args.subcommand == "demo":
            from .onboarding import demo, demo_text
            result = demo(agent=args.agent)
            print(json.dumps(result, indent=2) if args.json else demo_text(result))
            return 0 if result["status"] == "passed" else 1
        if args.subcommand == "open":
            from .onboarding import open_client
            return open_client(args.root, client=args.client, online=args.online, review=args.review,
                               dry_run=args.dry_run, client_args=launch_command, agent=args.agent)
        if args.subcommand == "check":
            from .presentation import scan_result
            report = Scanner(args.root, online=args.online).scan(args.level)
            print(json.dumps(report.full() if args.full else report.summary(), indent=2) if args.json else
                  scan_result(report, full=args.full))
            return {"no_findings": 0, "block": 1, "review": 2}[report.decision]
        if args.subcommand == "scan":
            report = Scanner(args.root, online=args.online).scan(args.level)
            print(json.dumps(report.full() if args.full else report.summary(), indent=2))
            return {"no_findings": 0, "block": 1, "review": 2}[report.decision]
        if args.subcommand == "serve":
            from .mcp import serve
            return serve(Scanner(args.root, online=args.online))
        if args.subcommand == "hook":
            from .hooks import run
            return run(online=args.online, agent=args.agent)
        if args.subcommand == "check-dependency":
            from .preflight import check_dependency
            result = check_dependency(args.ecosystem, args.name, args.version,
                                      registry=args.registry, online=args.online)
            print(json.dumps(result, indent=2))
            return {"no_findings": 0, "block": 1, "review": 2}[result["decision"]]
        if args.subcommand == "doctor":
            from .doctor import diagnose
            result = diagnose(args.root, settings=args.settings, probe_hooks=args.probe_hooks, agent=args.agent)
            if args.human:
                from .presentation import doctor_result
                print(doctor_result(result))
            else:
                print(json.dumps(result, indent=2))
            return 1 if result["status"] == "failed" else 0
        if args.subcommand in {"install-hooks", "uninstall-hooks"}:
            from .integration import configure
            from .agents import default_settings
            result = configure("install" if args.subcommand == "install-hooks" else "uninstall",
                               default_settings(args.agent, args.settings), args.project, dry_run=args.dry_run,
                               online=getattr(args, "online", False), agent=args.agent)
            if args.human:
                from .presentation import setup_result
                print(setup_result(result))
            else:
                print(json.dumps(result, indent=2))
            return 2 if result["status"] in {"disabled", "disabled_by_project", "conflict", "applied_with_warning"} else 0
        if args.subcommand == "launch":
            from .launcher import launch
            return launch(args.root, launch_command, online=args.online, review=args.review,
                          dry_run=args.dry_run, output_stream=sys.stdout if args.dry_run else sys.stderr)
        verdict = check_command(args.command)
        print(json.dumps(verdict))
        return {"no_objection": 0, "deny": 1, "ask": 2}[verdict["decision"]]
    except KeyboardInterrupt:
        print("Interrupted. If setup had begun applying changes, inspect the settings before retrying.", file=sys.stderr)
        return 130
    except (OSError, ValueError) as error:
        print("Protection Agency could not complete the check; no safety result asserted.", file=sys.stderr)
        if args.subcommand in {"setup", "open", "check", "demo"}:
            from .onboarding import error_hint
            print(error_hint(error), file=sys.stderr)
        return 3
