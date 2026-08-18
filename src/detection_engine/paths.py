from __future__ import annotations

from pathlib import Path


def find_repo_root() -> Path:
    for candidate in (Path.cwd(), *Path.cwd().parents):
        if (candidate / "detections" / "sigma").is_dir():
            return candidate
    package_root = Path(__file__).resolve().parents[2]
    if (package_root / "detections" / "sigma").is_dir():
        return package_root
    raise FileNotFoundError("could not find detections/sigma from the current directory")


PACKAGE_ROOT = find_repo_root()
DETECTIONS_ROOT = PACKAGE_ROOT / "detections"
SIGMA_ROOT = DETECTIONS_ROOT / "sigma"
SQL_ROOT = DETECTIONS_ROOT / "sql"
SAMPLES_ROOT = DETECTIONS_ROOT / "samples"
