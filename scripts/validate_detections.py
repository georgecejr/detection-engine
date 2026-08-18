#!/usr/bin/env python3
"""Validate the detections tree: Sigma YAML, matching SQL, and sample JSON."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS = ROOT / "detections"
SIGMA_ROOT = DETECTIONS / "sigma"
SQL_ROOT = DETECTIONS / "sql"
SAMPLES_ROOT = DETECTIONS / "samples"

REQUIRED_SIGMA_FIELDS = ("title", "id", "logsource", "detection")
SQL_HINTS = ("select", "with")


def fail(errors: list[str]) -> None:
    print("Detection validation failed:\n", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def validate_sigma_rule(path: Path, errors: list[str]) -> None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        errors.append(f"{relative(path)}: invalid YAML ({exc})")
        return

    if not isinstance(data, dict):
        errors.append(f"{relative(path)}: rule must be a YAML mapping")
        return

    for field in REQUIRED_SIGMA_FIELDS:
        if field not in data:
            errors.append(f"{relative(path)}: missing required field '{field}'")

    logsource = data.get("logsource")
    if logsource is not None and not isinstance(logsource, dict):
        errors.append(f"{relative(path)}: 'logsource' must be a mapping")

    detection = data.get("detection")
    if detection is not None and not isinstance(detection, dict):
        errors.append(f"{relative(path)}: 'detection' must be a mapping")
    elif isinstance(detection, dict) and "condition" not in detection:
        errors.append(f"{relative(path)}: 'detection.condition' is required")

    rel = path.relative_to(SIGMA_ROOT).with_suffix(".sql")
    sql_path = SQL_ROOT / rel
    if not sql_path.is_file():
        errors.append(
            f"{relative(path)}: missing matching SQL file {relative(sql_path)}"
        )


def validate_sql_file(path: Path, errors: list[str]) -> None:
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        errors.append(f"{relative(path)}: SQL file is empty")
        return
    lowered = content.lower()
    if not any(hint in lowered for hint in SQL_HINTS):
        errors.append(f"{relative(path)}: expected a SELECT or WITH query")


def validate_sample(path: Path, errors: list[str]) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"{relative(path)}: invalid JSON ({exc})")
        return

    if not isinstance(data, dict):
        errors.append(f"{relative(path)}: sample must be a JSON object")
        return

    for field in ("name", "logsource", "events"):
        if field not in data:
            errors.append(f"{relative(path)}: missing required field '{field}'")

    events = data.get("events")
    if events is not None:
        if not isinstance(events, list) or not events:
            errors.append(f"{relative(path)}: 'events' must be a non-empty array")
        elif not all(isinstance(event, dict) for event in events):
            errors.append(f"{relative(path)}: each event must be an object")


def main() -> None:
    errors: list[str] = []

    if not SIGMA_ROOT.is_dir():
        fail([f"missing directory {relative(SIGMA_ROOT)}"])
    if not SQL_ROOT.is_dir():
        fail([f"missing directory {relative(SQL_ROOT)}"])
    if not SAMPLES_ROOT.is_dir():
        fail([f"missing directory {relative(SAMPLES_ROOT)}"])

    sigma_rules = sorted(SIGMA_ROOT.rglob("*.yml")) + sorted(SIGMA_ROOT.rglob("*.yaml"))
    if not sigma_rules:
        errors.append(f"{relative(SIGMA_ROOT)}: no Sigma rules found")

    for rule in sigma_rules:
        validate_sigma_rule(rule, errors)

    sql_files = sorted(SQL_ROOT.rglob("*.sql"))
    if not sql_files:
        errors.append(f"{relative(SQL_ROOT)}: no SQL detections found")

    for sql_file in sql_files:
        validate_sql_file(sql_file, errors)
        rel = sql_file.relative_to(SQL_ROOT).with_suffix(".yml")
        yaml_alt = sql_file.relative_to(SQL_ROOT).with_suffix(".yaml")
        if not (SIGMA_ROOT / rel).is_file() and not (SIGMA_ROOT / yaml_alt).is_file():
            errors.append(
                f"{relative(sql_file)}: missing matching Sigma rule "
                f"{relative(SIGMA_ROOT / rel)}"
            )

    samples = sorted(SAMPLES_ROOT.glob("*.json"))
    if not samples:
        errors.append(f"{relative(SAMPLES_ROOT)}: no sample JSON files found")
    for sample in samples:
        validate_sample(sample, errors)

    if errors:
        fail(errors)

    print(
        f"Validated {len(sigma_rules)} Sigma rule(s), "
        f"{len(sql_files)} SQL file(s), and {len(samples)} sample(s)."
    )


if __name__ == "__main__":
    main()
