"""YAML-driven log source detection.

Detection rules come from each mapping config's ``detection:`` block - no
source-specific Python logic:

.. code-block:: yaml

    detection:
      required_fields: [eventSource, eventName]   # all must be present (dot paths ok)
      field_patterns:                              # fnmatch glob on the stringified value
        eventSource: "*.amazonaws.com"
      any_of_fields: [a, b]                        # at least one present (optional)

Rules are evaluated in descending ``priority`` order (ties broken by
source_name) so a more specific source always wins over a generic one.
Unknown events simply fail to match and are reported as ``undetected`` -
they are never silently dropped.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass
from typing import Any, Mapping

from app.mapping.resolver import get_path

logger = logging.getLogger("threatstream.detection")


@dataclass(frozen=True)
class DetectionResult:
    source_name: str
    priority: int


class SourceDetector:
    """Matches raw events against the detection blocks of loaded mappings."""

    def __init__(self, configs: Mapping[str, Mapping[str, Any]]):
        self._rules = sorted(
            (dict(c) for c in configs.values()),
            key=lambda c: (-c.get("priority", 0), str(c.get("source_name", ""))),
        )

    @property
    def source_names(self) -> list[str]:
        return [r["source_name"] for r in self._rules]

    def detect(self, event: Mapping[str, Any]) -> DetectionResult | None:
        if not isinstance(event, Mapping):
            return None
        for rule in self._rules:
            if self._matches(rule, event):
                return DetectionResult(rule["source_name"], rule.get("priority", 0))
        return None

    def _matches(self, rule: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
        detection = rule.get("detection") or {}

        for field in detection.get("required_fields") or []:
            if get_path(event, str(field)) is None:
                return False

        any_of = detection.get("any_of_fields") or []
        if any_of and all(get_path(event, str(f)) is None for f in any_of):
            return False

        for field, pattern in (detection.get("field_patterns") or {}).items():
            value = get_path(event, str(field))
            if value is None:
                return False
            if not fnmatch.fnmatchcase(str(value), str(pattern)):
                return False

        return True
