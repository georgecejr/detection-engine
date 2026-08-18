from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

from detection_engine.loader import load_rules, load_samples
from detection_engine.paths import DETECTIONS_ROOT, SAMPLES_ROOT, SIGMA_ROOT, SQL_ROOT

REQUIRED_SIGMA_FIELDS = ("title", "id", "logsource", "detection")
SQL_HINTS = ("select", "with")


def relative(path: Path, root: Path = DETECTIONS_ROOT.parent) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def collect_errors(
    *,
    sigma_root: Path | None = None,
    sql_root: Path | None = None,
    samples_root: Path | None = None,
) -> list[str]:
    sigma_root = sigma_root or SIGMA_ROOT
    sql_root = sql_root or SQL_ROOT
    samples_root = samples_root or SAMPLES_ROOT
    errors: list[str] = []

    if not sigma_root.is_dir():
        return [f"missing directory {relative(sigma_root)}"]
    if not sql_root.is_dir():
        return [f"missing directory {relative(sql_root)}"]
    if not samples_root.is_dir():
        return [f"missing directory {relative(samples_root)}"]

    sigma_rules = sorted(sigma_root.rglob("*.yml")) + sorted(sigma_root.rglob("*.yaml"))
    if not sigma_rules:
        errors.append(f"{relative(sigma_root)}: no Sigma rules found")

    for path in sigma_rules:
        _validate_sigma_rule(path, sigma_root, sql_root, errors)

    sql_files = sorted(sql_root.rglob("*.sql"))
    if not sql_files:
        errors.append(f"{relative(sql_root)}: no SQL detections found")

    for sql_file in sql_files:
        _validate_sql_file(sql_file, errors)
        yml = sigma_root / sql_file.relative_to(sql_root).with_suffix(".yml")
        yaml_path = sigma_root / sql_file.relative_to(sql_root).with_suffix(".yaml")
        if not yml.is_file() and not yaml_path.is_file():
            errors.append(
                f"{relative(sql_file)}: missing matching Sigma rule {relative(yml)}"
            )

    samples = sorted(samples_root.glob("*.json"))
    if not samples:
        errors.append(f"{relative(samples_root)}: no sample JSON files found")
    for sample in samples:
        _validate_sample(sample, errors)

    try:
        load_rules(sigma_root, sql_root)
        load_samples(samples_root)
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        errors.append(str(exc))

    return errors


def _validate_sigma_rule(
    path: Path, sigma_root: Path, sql_root: Path, errors: list[str]
) -> None:
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

    sql_path = sql_root / path.relative_to(sigma_root).with_suffix(".sql")
    if not sql_path.is_file():
        errors.append(f"{relative(path)}: missing matching SQL file {relative(sql_path)}")


def _validate_sql_file(path: Path, errors: list[str]) -> None:
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        errors.append(f"{relative(path)}: SQL file is empty")
        return
    lowered = content.lower()
    if not any(hint in lowered for hint in SQL_HINTS):
        errors.append(f"{relative(path)}: expected a SELECT or WITH query")


def _validate_sample(path: Path, errors: list[str]) -> None:
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


def main() -> int:
    errors = collect_errors()
    if errors:
        print("Detection validation failed:\n", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    rules = load_rules()
    samples = load_samples()
    event_count = sum(len(sample.events) for sample in samples)
    print(
        f"Validated {len(rules)} Sigma rule(s), "
        f"{sum(1 for rule in rules if rule.sql_path)} SQL file(s), "
        f"and {len(samples)} sample(s) ({event_count} event(s))."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
