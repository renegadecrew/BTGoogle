#!/usr/bin/env python3
"""Deprecated entry point for the BTGoogle gate.

The pinned, installed gate is ``scope_gate_v2.py``. This file used to carry a
second implementation of the same rules, and the two drifted: a fix landed in
one copy but not the other, while hooks.json ran the copy the tests did not
exercise. It now delegates to the pinned gate so there is exactly one decision
engine.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scope_gate_v2 import run  # noqa: E402

if __name__ == "__main__":
    run()
