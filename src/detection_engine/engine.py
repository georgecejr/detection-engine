from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from detection_engine.loader import event_id, load_rules, load_samples
from detection_engine.matcher import matches
from detection_engine.models import Rule, Sample
from detection_engine.paths import SAMPLES_ROOT, SIGMA_ROOT, SQL_ROOT


@dataclass(frozen=True)
class Alert:
    rule: Rule
    event: dict[str, Any]
    sample: Sample

    @property
    def event_id(self) -> str:
        return event_id(self.event)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "rule": self.rule.title,
            "level": self.rule.level,
            "product": self.rule.product,
            "sample": self.sample.name,
            "event_id": self.event_id,
            "event_type": _event_type(self.event),
        }


def _event_type(event: dict[str, Any]) -> str | None:
    if event.get("eventName"):
        return str(event["eventName"])
    for key in ("eventType", "eventtype", "event_type"):
        if event.get(key):
            return str(event[key])
    return None


def run_detections(
    *,
    sigma_root: Path | None = None,
    sql_root: Path | None = None,
    samples_root: Path | None = None,
) -> list[Alert]:
    rules = load_rules(sigma_root or SIGMA_ROOT, sql_root or SQL_ROOT)
    samples = load_samples(samples_root or SAMPLES_ROOT)
    alerts: list[Alert] = []
    for sample in samples:
        product = sample.logsource.lower()
        for event in sample.events:
            for rule in rules:
                if product and rule.product and rule.product != product:
                    continue
                if matches(rule, event):
                    alerts.append(Alert(rule=rule, event=event, sample=sample))
    return alerts
