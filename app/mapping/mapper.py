"""The YAML-driven OCSF mapping engine.

Maps a raw source event to a normalized OCSF event using nothing but the
per-source YAML config - no per-source Python code. A mapping config controls:

* the OCSF class/category/severity defaults (``ocsf:``),
* the activity resolution, including per-activity class overrides
  (``activity:`` - e.g. CloudTrail ``ConsoleLogin`` becomes Authentication
  while other API calls stay API Activity),
* the output fields (``fields:`` - nested dict of templates / enums / nodes).

Design notes:

* Activity is resolved *first* because its entry may override class/category/
  severity for this specific event.
* ``ocsf.on_failure`` bumps severity whenever the mapped event failed
  (``status_id == 2``), keeping severity policy data-driven too.
* ``time`` is mandatory and always normalized to epoch milliseconds via
  :func:`resolver.to_epoch_ms`.
* ``metadata.uid`` is intentionally NOT set here - it is derived from the
  deterministic content fingerprint during deduplication (idempotency).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Mapping

from app.exceptions import MappingError
from app.mapping import resolver

logger = logging.getLogger("threatstream.mapping")

OCSF_VERSION = "1.3.0"

SEVERITY_NAMES = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
}


class EventMapper:
    """Maps raw events to OCSF events using loaded YAML mapping configs."""

    def __init__(self, configs: Mapping[str, Mapping[str, Any]]):
        self._configs = dict(configs)

    @property
    def source_names(self) -> list[str]:
        return sorted(self._configs)

    def map_event(self, event: Mapping[str, Any], source_name: str) -> dict[str, Any]:
        cfg = self._configs.get(source_name)
        if cfg is None:
            raise MappingError(f"no mapping config for source '{source_name}'")
        try:
            return self._map(event, cfg)
        except MappingError:
            raise
        except Exception as exc:  # config/runtime errors become MappingError
            raise MappingError(f"[{source_name}] mapping failed: {exc}") from exc

    # ------------------------------------------------------------------ #
    def _map(self, event: Mapping[str, Any], cfg: Mapping[str, Any]) -> dict[str, Any]:
        source = cfg["source_name"]
        ocsf = cfg["ocsf"]

        activity_id, activity_name, overrides = self._resolve_activity(cfg, event)

        class_uid = int(overrides.get("class_uid", ocsf["class_uid"]))
        class_name = str(overrides.get("class_name", ocsf["class_name"]))
        category_uid = int(overrides.get("category_uid", ocsf["category_uid"]))
        category_name = str(overrides.get("category_name", ocsf["category_name"]))
        severity_id = int(overrides.get("severity_id", ocsf.get("severity_id", 1)))
        severity = str(overrides.get("severity", ocsf.get("severity", SEVERITY_NAMES.get(severity_id, "Unknown"))))

        fields = self._map_fields(cfg.get("fields") or {}, event)

        if "time" not in fields:
            raise MappingError(f"[{source}] mapping produced no 'time' field")
        time_ms = resolver.to_epoch_ms(fields.pop("time"))

        on_failure = ocsf.get("on_failure")
        if on_failure and fields.get("status_id") == 2:
            severity_id = int(on_failure.get("severity_id", severity_id))
            severity = str(on_failure.get("severity", severity))

        meta_cfg = cfg.get("metadata") or {}
        timestamp_ingest = datetime.now(timezone.utc)
        ocsf_event: dict[str, Any] = {
            "class_uid": class_uid,
            "class_name": class_name,
            "category_uid": category_uid,
            "category_name": category_name,
            "activity_id": activity_id,
            "activity_name": activity_name,
            "severity_id": severity_id,
            "severity": severity,
            "status_id": fields.pop("status_id", None),
            "status": fields.pop("status", None),
            "type_uid": class_uid * 100 + activity_id,
            "type_name": f"{class_name}: {activity_name}",
            "time": time_ms,
        }
        ocsf_event = {k: v for k, v in ocsf_event.items() if v is not None}
        ocsf_event.update(fields)
        ocsf_event["metadata"] = {
            "version": OCSF_VERSION,
            "product": {
                "name": str(meta_cfg.get("product_name", "Unknown")),
                "vendor_name": str(meta_cfg.get("vendor_name", "Unknown")),
            },
            "log_source": source,
            "logged_time": int(timestamp_ingest.timestamp() * 1000),
            # uid assigned by the pipeline after content fingerprinting
        }
        return ocsf_event

    # ------------------------------------------------------------------ #
    def _resolve_activity(
        self, cfg: Mapping[str, Any], event: Mapping[str, Any]
    ) -> tuple[int, str, dict[str, Any]]:
        activity_cfg = cfg.get("activity") or {}
        default = activity_cfg.get("default") or {"uid": 0, "name": "Unknown"}

        field = activity_cfg.get("field")
        if not field:
            return int(default.get("uid", 0)), str(default.get("name", "Unknown")), {}

        value = resolver.resolve_template(field, event)
        match = resolver.match_pattern_map(value, activity_cfg.get("map") or {}, default=default)
        if not isinstance(match, Mapping):
            match = default

        uid = int(match.get("uid", 0))
        name = str(match.get("name", "Unknown"))
        overrides = {k: v for k, v in match.items() if k not in ("uid", "name")}
        return uid, name, overrides

    def _map_fields(self, spec: Mapping[str, Any], event: Mapping[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, node in spec.items():
            value = self._resolve_node(node, event)
            if value is None:
                continue
            if isinstance(value, Mapping) and not value:
                continue
            out[key] = value
        return out

    def _resolve_node(self, node: Any, event: Mapping[str, Any]) -> Any:
        if isinstance(node, Mapping):
            if "enum" in node:
                return resolver.resolve_enum(node["enum"], event)
            if "value" in node:
                value = resolver.resolve_template(node["value"], event)
                if value is None:
                    return node.get("default")
                fmt = node.get("format")
                if fmt and isinstance(value, str):
                    # Parse now so downstream time normalization gets a datetime
                    return datetime.strptime(value.strip(), fmt)
                return value
            # plain nested structure
            nested: dict[str, Any] = {}
            for key, sub in node.items():
                value = self._resolve_node(sub, event)
                if value is None:
                    continue
                if isinstance(value, Mapping) and not value:
                    continue
                nested[key] = value
            return nested
        return resolver.resolve_template(node, event)
