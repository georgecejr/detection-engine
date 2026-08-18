from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Rule:
    path: Path
    title: str
    id: str
    detection: dict[str, Any]
    logsource: dict[str, Any] = field(default_factory=dict)
    status: str = ""
    description: str = ""
    level: str = "informational"
    tags: tuple[str, ...] = ()
    sql_path: Path | None = None

    @property
    def product(self) -> str:
        return str(self.logsource.get("product", "")).lower()

    @property
    def service(self) -> str:
        return str(self.logsource.get("service", "")).lower()

    @property
    def stem(self) -> str:
        return self.path.stem


@dataclass(frozen=True)
class Sample:
    path: Path
    name: str
    logsource: str
    events: list[dict[str, Any]]
    expected_alerts: tuple[tuple[str, str], ...] = ()
    description: str = ""
