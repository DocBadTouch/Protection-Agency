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
    launch_parser = commands.add_parser("launch", help="Inspect before launching a trusted external client; does not provide a sandbox")
    launch_parser.add_argument("root", type=Path)
    launch_parser.add_argument("--online", action="store_true")
    launch_parser.add_argument("--review", action="store_true", help="Permit explicit terminal review of lower-priority findings when coverage is complete")
    launch_parser.add_argument("--dry-run", action="store_true", help="Print preflight only; never start a client")
    argv = list(sys.argv[1:] if argv is None else argv)
    launch_command = []
    before_separator = argv[:argv.index("--")] if "--" in argv else argv
    if argv[:1] == ["launch"] and not {"--help", "-h"}.intersection(before_separator):
        if "--" not in argv:
            parser.error("launch requires -- followed by an absolute client executable and its arguments")
        index = argv.index("--")
        launch_command, argv = argv[index + 1:], argv[:index]
        if not launch_command:
            parser.error("launch requires a client executable after --")
    args = parser.parse_args(argv)
    try:
        if args.subcommand == "scan":
            report = Scanner(args.root, online=args.online).scan(args.level)
            print(json.dumps(report.full() if args.full else report.summary(), indent=2))
            return {"no_findings": 0, "block": 1, "review": 2}[report.decision]
        if args.subcommand == "serve":
            from .mcp import serve
            return serve(Scanner(args.root, online=args.online))
        if args.subcommand == "hook":
            from .hooks import run
            return run(online=args.online)
        if args.subcommand == "check-dependency":
            from .preflight import check_dependency
            result = check_dependency(args.ecosystem, args.name, args.version,
                                      registry=args.registry, online=args.online)
            print(json.dumps(result, indent=2))
            return {"no_findings": 0, "block": 1, "review": 2}[result["decision"]]
        if args.subcommand == "doctor":
            from .doctor import diagnose
            result = diagnose(args.root)
            print(json.dumps(result, indent=2))
            return 1 if result["status"] == "failed" else 0
        if args.subcommand == "launch":
            from .launcher import launch
            return launch(args.root, launch_command, online=args.online, review=args.review,
                          dry_run=args.dry_run, output_stream=sys.stdout if args.dry_run else sys.stderr)
        verdict = check_command(args.command)
        print(json.dumps(verdict))
        return {"no_objection": 0, "deny": 1, "ask": 2}[verdict["decision"]]
    except (OSError, ValueError):
        print("Protection Agency could not complete the check; no safety result asserted.", file=sys.stderr)
        return 3
