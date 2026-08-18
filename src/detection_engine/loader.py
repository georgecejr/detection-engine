from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from detection_engine.models import Rule, Sample
from detection_engine.paths import SAMPLES_ROOT, SIGMA_ROOT, SQL_ROOT


def _rule_paths(sigma_root: Path) -> list[Path]:
    return sorted(sigma_root.rglob("*.yml")) + sorted(sigma_root.rglob("*.yaml"))


def load_rule(path: Path, sigma_root: Path | None = None, sql_root: Path | None = None) -> Rule:
    sigma_root = sigma_root or SIGMA_ROOT
    sql_root = sql_root or SQL_ROOT
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: rule must be a YAML mapping")

    relative = path.relative_to(sigma_root).with_suffix(".sql")
    sql_path = sql_root / relative
    tags = data.get("tags") or []
    description = data.get("description") or ""
    if isinstance(description, str):
        description = " ".join(description.split())

    return Rule(
        path=path,
        title=str(data.get("title", path.stem)),
        id=str(data.get("id", "")),
        detection=data.get("detection") or {},
        logsource=data.get("logsource") or {},
        status=str(data.get("status", "")),
        description=description,
        level=str(data.get("level", "informational")),
        tags=tuple(str(tag) for tag in tags),
        sql_path=sql_path if sql_path.is_file() else None,
    )


def load_rules(sigma_root: Path | None = None, sql_root: Path | None = None) -> list[Rule]:
    sigma_root = sigma_root or SIGMA_ROOT
    sql_root = sql_root or SQL_ROOT
    return [load_rule(path, sigma_root, sql_root) for path in _rule_paths(sigma_root)]


def _event_id(event: dict[str, Any]) -> str:
    for key in ("uuid", "eventID", "event_id", "id"):
        value = event.get(key)
        if value:
            return str(value)
    return ""


def load_sample(path: Path) -> Sample:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: sample must be a JSON object")

    expected: list[tuple[str, str]] = []
    for item in data.get("expected_alerts") or []:
        if not isinstance(item, dict):
            continue
        event_id = str(item.get("event_id", ""))
        rule_id = str(item.get("rule_id", ""))
        if event_id and rule_id:
            expected.append((event_id, rule_id))

    events = data.get("events") or []
    if not isinstance(events, list):
        raise ValueError(f"{path}: 'events' must be an array")

    return Sample(
        path=path,
        name=str(data.get("name", path.stem)),
        logsource=str(data.get("logsource", "")).lower(),
        events=[event for event in events if isinstance(event, dict)],
        expected_alerts=tuple(expected),
        description=str(data.get("description", "")),
    )


def load_samples(samples_root: Path | None = None) -> list[Sample]:
    samples_root = samples_root or SAMPLES_ROOT
    return [load_sample(path) for path in sorted(samples_root.glob("*.json"))]


def event_id(event: dict[str, Any]) -> str:
    return _event_id(event)
