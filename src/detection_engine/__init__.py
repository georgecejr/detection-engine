"""Detection engine: load Sigma rules and evaluate them against sample events."""

from detection_engine.engine import Alert, run_detections
from detection_engine.loader import load_rules, load_samples
from detection_engine.models import Rule, Sample

__all__ = [
    "Alert",
    "Rule",
    "Sample",
    "load_rules",
    "load_samples",
    "run_detections",
]
