from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import Settings  # noqa: E402
from app.mapping.mapping_loader import load_mappings  # noqa: E402


@pytest.fixture
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture
def mappings(project_root) -> dict:
    """Real mapping configs from config/mappings/."""
    return load_mappings(project_root / "config" / "mappings")


@pytest.fixture
def make_settings(tmp_path, project_root):
    """Settings factory writing all pipeline output into a pytest tmp dir."""

    def _make(**overrides):
        data = {
            "paths": {
                "mappings_dir": str(project_root / "config" / "mappings"),
                "output_dir": str(tmp_path / "output"),
                "errors_dir": str(tmp_path / "output" / "_errors"),
                "runs_dir": str(tmp_path / "output" / "_runs"),
                "state_dir": str(tmp_path / "state"),
            },
            "pipeline": {"deduplication": {"enabled": True, "window_minutes": 60, "persist": True}},
        }
        data.update(overrides)
        # project_root = the real repo (mappings/ + db/schema.sql live there);
        # only *generated* data goes into tmp_path via absolute paths above.
        return Settings.from_dict(data, project_root)

    return _make
