#!/usr/bin/env python3
"""VibeHacking CLI adapter; use: python TOOLS/mael_suite.py --help."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from MAEL.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
