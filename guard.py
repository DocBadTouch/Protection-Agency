"""Dependency-free launcher. Prefer: python3 -I /trusted/path/guard.py ..."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from protection_agency.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
