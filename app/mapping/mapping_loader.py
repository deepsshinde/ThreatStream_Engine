"""Loads and sanity-checks the per-source YAML mapping configs.

Each file in ``config/mappings/`` is a single mapping config containing at
minimum ``source_name``, ``detection`` and ``ocsf`` sections. All configs are
validated at pipeline startup so a broken mapping fails fast with a clear
message instead of silently dropping events at runtime.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Mapping

import yaml

from app.exceptions import ConfigError

logger = logging.getLogger("threatstream.mapping.loader")

REQUIRED_KEYS = ("source_name", "detection", "ocsf")
REQUIRED_OCSF_KEYS = ("class_uid", "class_name", "category_uid", "category_name")


def _validate_config(raw: Mapping[str, Any], path: Path) -> dict[str, Any]:
    for key in REQUIRED_KEYS:
        if key not in raw:
            raise ConfigError(f"mapping {path}: missing required key '{key}'")
    ocsf = raw["ocsf"]
    if not isinstance(ocsf, Mapping):
        raise ConfigError(f"mapping {path}: 'ocsf' must be a mapping")
    for key in REQUIRED_OCSF_KEYS:
        if key not in ocsf:
            raise ConfigError(f"mapping {path}: 'ocsf.{key}' is required")
    detection = raw["detection"]
    if not isinstance(detection, Mapping):
        raise ConfigError(f"mapping {path}: 'detection' must be a mapping")
    if not detection.get("required_fields") and not detection.get("field_patterns"):
        raise ConfigError(
            f"mapping {path}: detection needs 'required_fields' and/or 'field_patterns'"
        )
    config = dict(raw)
    config["source_name"] = str(config["source_name"])
    config["priority"] = int(config.get("priority", 0))
    return config


def load_mapping_file(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in mapping file {path}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise ConfigError(f"mapping file {path} must contain a YAML mapping")
    return _validate_config(raw, path)


def load_mappings(mappings_dir: str | Path) -> dict[str, dict[str, Any]]:
    """Load every ``*.yml``/``*.yaml`` in the directory, keyed by source_name."""
    directory = Path(mappings_dir)
    if not directory.is_dir():
        raise ConfigError(f"mappings directory not found: {directory}")

    configs: dict[str, dict[str, Any]] = {}
    files = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    for path in files:
        config = load_mapping_file(path)
        name = config["source_name"]
        if name in configs:
            raise ConfigError(f"duplicate source_name '{name}' in {path}")
        configs[name] = config
        logger.debug("Loaded mapping %s (priority=%s) from %s", name, config["priority"], path)

    if not configs:
        raise ConfigError(f"no mapping files (*.yml) found in {directory}")
    return configs
