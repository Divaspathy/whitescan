#!/usr/bin/env python3
"""WhiteScan launcher — keeps `python whitescan.py` and sudo install working."""
import os
import signal
import sys

# Allow running from a source checkout without installation
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from whitescan.__main__ import entry  # noqa: E402


if __name__ == "__main__":
    entry()
