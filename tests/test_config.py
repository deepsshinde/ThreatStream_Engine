import os

import pytest

from app.config import Settings, expand_env, load_settings, to_bool


class TestToBool:
    @pytest.mark.parametrize(
        "value,expected",
        [
            (True, True),
            ("true", True),
            ("True", True),
            ("1", True),
            ("yes", True),
            ("on", True),
            ("false", False),
            ("FALSE", False),
            ("0", False),
            ("no", False),
            ("anything-else", False),
            (0, False),
            (1, True),
        ],
    )
    def test_values(self, value, expected):
        assert to_bool(value) is expected


class TestExpandEnv:
    def test_var_expansion(self, monkeypatch):
        monkeypatch.setenv("DB_HOST", "db.internal")
        assert expand_env("host=${DB_HOST}") == "host=db.internal"

    def test_default_used_when_unset(self, monkeypatch):
        monkeypatch.delenv("UNSET_VAR_XYZ", raising=False)
        assert expand_env("${UNSET_VAR_XYZ:-fallback}") == "fallback"

    def test_unexpanded_marker_left_visible(self, monkeypatch):
        monkeypatch.delenv("UNSET_VAR_XYZ", raising=False)
        assert expand_env("${UNSET_VAR_XYZ}") == "${UNSET_VAR_XYZ}"

    def test_nested_structures(self, monkeypatch):
        monkeypatch.setenv("PGPORT", "5544")
        out = expand_env({"a": ["${PGPORT}", {"b": "${MISSING:-x}"}]})
        assert out == {"a": ["5544", {"b": "x"}]}


def _write_project(root, postgres_enabled="${POSTGRES_ENABLED:-false}"):
    (root / "config").mkdir(parents=True)
    (root / "config" / "settings.yml").write_text(
        f"""
project: test-project
paths:
  mappings_dir: config/mappings
  output_dir: data/output
pipeline:
  deduplication:
    enabled: true
    window_minutes: 5
    persist: false
postgres:
  enabled: {postgres_enabled}
  host: ${{POSTGRES_HOST:-default-localhost}}
  port: ${{POSTGRES_PORT:-5432}}
  dbname: ${{POSTGRES_DB:-threatstream}}
  user: ${{POSTGRES_USER:-threatstream}}
  password: ${{POSTGRES_PASSWORD:-threatstream}}
""",
        encoding="utf-8",
    )
    return root / "config" / "settings.yml"


class TestLoadSettings:
    def test_env_expansion_and_defaults(self, tmp_path, monkeypatch):
        config = _write_project(tmp_path)
        monkeypatch.delenv("POSTGRES_HOST", raising=False)
        monkeypatch.setenv("POSTGRES_HOST", "db.internal")
        settings = load_settings(config)
        assert settings.postgres.host == "db.internal"
        assert settings.postgres.port == 5432
        assert settings.postgres.enabled is False  # default from :-false
        assert settings.project_root == tmp_path
        assert settings.dedup_window_minutes == 5

    def test_dotenv_file_is_loaded(self, tmp_path, monkeypatch):
        config = _write_project(tmp_path)
        for key in ("POSTGRES_HOST", "POSTGRES_ENABLED"):
            monkeypatch.delenv(key, raising=False)
        (tmp_path / ".env").write_text(
            "POSTGRES_HOST=from-dotenv\nPOSTGRES_ENABLED=true\n", encoding="utf-8"
        )
        settings = load_settings(config)
        assert settings.postgres.host == "from-dotenv"
        assert settings.postgres.enabled is True
        # cleanup: load_dotenv wrote into os.environ directly
        monkeypatch.delenv("POSTGRES_HOST", raising=False)
        monkeypatch.delenv("POSTGRES_ENABLED", raising=False)

    def test_real_env_var_beats_dotenv(self, tmp_path, monkeypatch):
        config = _write_project(tmp_path)
        (tmp_path / ".env").write_text("POSTGRES_HOST=from-dotenv\n", encoding="utf-8")
        monkeypatch.setenv("POSTGRES_HOST", "from-real-env")
        settings = load_settings(config)
        assert settings.postgres.host == "from-real-env"

    def test_postgres_enabled_truthy_string(self, tmp_path, monkeypatch):
        config = _write_project(tmp_path)
        monkeypatch.setenv("POSTGRES_ENABLED", "true")
        settings = load_settings(config)
        assert settings.postgres.enabled is True
