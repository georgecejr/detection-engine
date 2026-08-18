#!/usr/bin/env python3
"""Validate the detections tree: Sigma YAML, matching SQL, and sample JSON."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from detection_engine.validate import main

if __name__ == "__main__":
    raise SystemExit(main())
