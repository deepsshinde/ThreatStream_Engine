"""OCSF event validation.

Validates the structural guarantees the downstream layers rely on:

* required top-level fields are present and correctly typed,
* ``class_uid``/``class_name``/``category_uid``/``category_name`` are
  consistent with the classes this platform emits,
* ``activity_id``, ``severity_id``/``severity``, ``status_id``/``status``
  are in range and consistent,
* ``time`` is a plausible epoch-milliseconds integer,
* ``type_uid == class_uid * 100 + activity_id``,
* nested structures (``actor``, ``src_endpoint``, ``metadata`` ...) are
  type-correct when present.

Scope note: this validates structure and a registry of OCSF classes the
platform uses - it is not a full JSON-Schema validation of the entire OCSF
schema (see README "Limitations").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

# Registry of OCSF classes this platform emits: class_uid -> (class_name, category_uid, category_name)
CLASS_REGISTRY: dict[int, tuple[str, int, str]] = {
    3001: ("Account Change", 3, "Identity & Access Management"),
    3002: ("Authentication", 3, "Identity & Access Management"),
    4001: ("Network Activity", 4, "Network Activity"),
    6003: ("API Activity", 6, "Application Activity"),
    2004: ("Detection Finding", 2, "Findings"),
}

SEVERITY_REGISTRY = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
}

STATUS_REGISTRY = {0: "Unknown", 1: "Success", 2: "Failure", 99: "Other"}

MIN_TIME_MS = 946_684_800_000  # 2000-01-01
MAX_TIME_MS = 4_102_444_800_000  # 2100-01-01


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "errors": list(self.errors)}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class OCSFValidator:
    """Structural validator for normalized OCSF events."""

    def validate(self, event: Any) -> ValidationResult:
        errors: list[str] = []
        if not isinstance(event, Mapping):
            return ValidationResult(valid=False, errors=["event is not an object"])

        self._check_required(event, errors)
        if errors:
            return ValidationResult(valid=False, errors=errors)

        self._check_class_consistency(event, errors)
        self._check_activity(event, errors)
        self._check_severity(event, errors)
        self._check_status(event, errors)
        self._check_time(event, errors)
        self._check_type_uid(event, errors)
        self._check_nested(event, errors)
        self._check_metadata(event, errors)
        return ValidationResult(valid=not errors, errors=errors)

    # ------------------------------------------------------------------ #
    def _check_required(self, event: Mapping[str, Any], errors: list[str]) -> None:
        required_int = ["class_uid", "category_uid", "activity_id", "severity_id", "time", "type_uid"]
        required_str = ["class_name", "category_name", "activity_name", "severity"]
        for key in required_int:
            if key not in event:
                errors.append(f"Missing required field: {key}")
            elif not _is_int(event[key]):
                errors.append(f"Field '{key}' must be an integer, got {type(event[key]).__name__}")
        for key in required_str:
            if key not in event:
                errors.append(f"Missing required field: {key}")
            elif not isinstance(event[key], str) or not event[key]:
                errors.append(f"Field '{key}' must be a non-empty string")

    def _check_class_consistency(self, event: Mapping[str, Any], errors: list[str]) -> None:
        class_uid = event["class_uid"]
        known = CLASS_REGISTRY.get(class_uid)
        if known is None:
            errors.append(f"Unknown class_uid: {class_uid}")
            return
        name, category_uid, category_name = known
        if event["class_name"] != name:
            errors.append(f"class_name '{event['class_name']}' does not match class_uid {class_uid} ('{name}')")
        if event["category_uid"] != category_uid:
            errors.append(f"category_uid {event['category_uid']} does not match class_uid {class_uid} (expected {category_uid})")
        if event["category_name"] != category_name:
            errors.append(f"category_name '{event['category_name']}' does not match class_uid {class_uid} (expected '{category_name}')")

    def _check_activity(self, event: Mapping[str, Any], errors: list[str]) -> None:
        if not 0 <= event["activity_id"] <= 99:
            errors.append(f"activity_id {event['activity_id']} out of range (0-99)")

    def _check_severity(self, event: Mapping[str, Any], errors: list[str]) -> None:
        sev_id = event["severity_id"]
        if sev_id not in SEVERITY_REGISTRY:
            errors.append(f"severity_id {sev_id} out of range (0-6)")
        elif event["severity"] != SEVERITY_REGISTRY[sev_id]:
            errors.append(f"severity '{event['severity']}' does not match severity_id {sev_id} ('{SEVERITY_REGISTRY[sev_id]}')")

    def _check_status(self, event: Mapping[str, Any], errors: list[str]) -> None:
        if "status_id" in event:
            status_id = event["status_id"]
            if not _is_int(status_id):
                errors.append("Field 'status_id' must be an integer")
            elif status_id not in STATUS_REGISTRY:
                errors.append(f"status_id {status_id} is not a valid status (0,1,2,99)")
            elif "status" in event and event["status"] != STATUS_REGISTRY[status_id]:
                errors.append(f"status '{event['status']}' does not match status_id {status_id}")

    def _check_time(self, event: Mapping[str, Any], errors: list[str]) -> None:
        time_ms = event["time"]
        if not MIN_TIME_MS <= time_ms <= MAX_TIME_MS:
            errors.append(f"time {time_ms} is not a plausible epoch-milliseconds timestamp")
        for optional in ("start_time", "end_time"):
            if optional in event and not _is_int(event[optional]):
                errors.append(f"Field '{optional}' must be an integer (epoch milliseconds)")

    def _check_type_uid(self, event: Mapping[str, Any], errors: list[str]) -> None:
        expected = event["class_uid"] * 100 + event["activity_id"]
        if event["type_uid"] != expected:
            errors.append(f"type_uid {event['type_uid']} != class_uid*100+activity_id ({expected})")

    def _check_nested(self, event: Mapping[str, Any], errors: list[str]) -> None:
        path_checks = [
            (("actor", "user", "name"), str),
            (("actor", "user", "type"), str),
            (("src_endpoint", "ip"), str),
            (("src_endpoint", "port"), int),
            (("dst_endpoint", "ip"), str),
            (("dst_endpoint", "port"), int),
            (("api", "operation"), str),
            (("cloud", "region"), str),
        ]
        for path, expected_type in path_checks:
            value = event
            for part in path:
                value = value.get(part) if isinstance(value, Mapping) else None
            if value is None:
                continue
            ok = _is_int(value) if expected_type is int else isinstance(value, expected_type)
            if not ok:
                dotted = ".".join(path)
                errors.append(f"Field '{dotted}' must be of type {expected_type.__name__}, got {type(value).__name__}")

    def _check_metadata(self, event: Mapping[str, Any], errors: list[str]) -> None:
        metadata = event.get("metadata")
        if metadata is None:
            errors.append("Missing required field: metadata")
            return
        if not isinstance(metadata, Mapping):
            errors.append("Field 'metadata' must be an object")
            return
        product = metadata.get("product")
        if not isinstance(product, Mapping) or not isinstance(product.get("name"), str) or not product.get("name"):
            errors.append("metadata.product.name must be a non-empty string")
        if "uid" in metadata and not isinstance(metadata["uid"], str):
            errors.append("metadata.uid must be a string")
