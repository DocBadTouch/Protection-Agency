"""Dependency-free launcher. Prefer: python3 -I /trusted/path/guard.py ..."""
from pathlib import Path
import sys

if sys.version_info < (3, 11):
    print("Protection Agency needs Python 3.11 or newer. Check python3 --version and select a supported interpreter.", file=sys.stderr)
    raise SystemExit(3)

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from protection_agency.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
