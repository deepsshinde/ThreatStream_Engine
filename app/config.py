"""Settings loading for ThreatStream Engine.

Configuration lives in ``config/settings.yml`` (relative to the project root)
using plain PyYAML - no heavyweight config framework.

Two small but important features:

* **No hardcoded credentials.** Strings may contain ``${VAR}`` /
  ``${VAR:-default}``, expanded from the process environment.
* **``.env`` support without a dependency.** ``<project root>/.env`` is parsed
  (``KEY=VALUE`` lines) into the environment before expansion; real
  environment variables always win over ``.env`` values.

The project root is resolved from ``THREATSTREAM_HOME``, falling back to the
directory that contains the ``app`` package.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from app.exceptions import ConfigError

DEFAULT_LOG_FORMAT = "%(asctime)s %(levelname)-5s %(name)s | %(message)s"
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")
_TRUE_VALUES = {"1", "true", "yes", "on"}


def to_bool(value: Any) -> bool:
    """Parse YAML/env booleans without the classic bool("false") == True footgun."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in _TRUE_VALUES
    return bool(value)


def expand_env(value: Any) -> Any:
    """Recursively expand ${VAR} / ${VAR:-default} in strings."""

    def _sub(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in os.environ:
            return os.environ[name]
        if default is not None:
            return default
        return match.group(0)  # leave as-is; downstream validation will complain clearly

    if isinstance(value, str):
        return _ENV_VAR_RE.sub(_sub, value)
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    if isinstance(value, Mapping):
        return {k: expand_env(v) for k, v in value.items()}
    return value


def load_dotenv(path: Path) -> int:
    """Load KEY=VALUE pairs into os.environ (without overriding real env vars)."""
    loaded = 0
    if not path.is_file():
        return 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val
            loaded += 1
    return loaded


def default_project_root() -> Path:
    """Project root = env var override, else the package's parent directory."""
    env = os.environ.get("THREATSTREAM_HOME")
    if env:
        return Path(env).resolve()
    return Path(__file__).resolve().parents[1]


def _rooted(root: Path, value: str) -> Path:
    p = Path(os.path.expanduser(str(value)))
    return p if p.is_absolute() else (root / p)


@dataclass
class PostgresSettings:
    enabled: bool = False
    host: str = "localhost"
    port: int = 5432
    dbname: str = "threatstream"
    user: str = "threatstream"
    password: str = "threatstream"
    conninfo_override: str | None = None
    connect_timeout: int = 5

    @property
    def conninfo(self) -> str:
        if self.conninfo_override:
            return self.conninfo_override
        return (
            f"host={self.host} port={self.port} dbname={self.dbname} "
            f"user={self.user} password={self.password} connect_timeout={self.connect_timeout}"
        )

    @property
    def describe(self) -> str:
        if self.conninfo_override:
            return "custom DSN"
        return f"{self.user}@{self.host}:{self.port}/{self.dbname}"

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "PostgresSettings":
        conninfo = str(data.get("conninfo", "") or "").strip()
        return cls(
            enabled=to_bool(data.get("enabled", False)),
            host=str(data.get("host", "localhost")),
            port=int(data.get("port", 5432)),
            dbname=str(data.get("dbname", "threatstream")),
            user=str(data.get("user", "threatstream")),
            password=str(data.get("password", "")),
            conninfo_override=conninfo or None,
            connect_timeout=int(data.get("connect_timeout", 5)),
        )


@dataclass
class KafkaSettings:
    enabled: bool = False
    bootstrap_servers: str = "localhost:9092"
    topic: str = "security-logs"
    group_id: str = "threatstream-consumer"
    auto_offset_reset: str = "earliest"

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "KafkaSettings":
        return cls(
            enabled=to_bool(data.get("enabled", False)),
            bootstrap_servers=str(data.get("bootstrap_servers", "localhost:9092")),
            topic=str(data.get("topic", "security-logs")),
            group_id=str(data.get("group_id", "threatstream-consumer")),
            auto_offset_reset=str(data.get("auto_offset_reset", "earliest")),
        )


@dataclass
class AnalysisSettings:
    """Security analysis (correlation + RAG + LLM findings)."""

    enabled: bool = False
    llm: str = "auto"  # auto | ollama | fallback
    max_candidates: int = 200

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AnalysisSettings":
        return cls(
            enabled=to_bool(data.get("enabled", False)),
            llm=str(data.get("llm", "auto")),
            max_candidates=int(data.get("max_candidates", 200)),
        )


@dataclass
class RagSettings:
    data_dir: Path = field(default_factory=lambda: Path("data/mitre"))
    top_k: int = 5
    similarity_threshold: float = 0.35
    embedder: str = "auto"  # auto | sentence-transformers | hashing

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], root: Path) -> "RagSettings":
        return cls(
            data_dir=_rooted(root, str(data.get("data_dir", "data/mitre"))),
            top_k=int(data.get("top_k", 5)),
            similarity_threshold=float(data.get("similarity_threshold", 0.35)),
            embedder=str(data.get("embedder", "auto")),
        )


@dataclass
class OllamaSettings:
    base_url: str = "http://localhost:11434"
    model: str = "llama3.2:3b"
    timeout_sec: float = 30.0

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "OllamaSettings":
        return cls(
            base_url=str(data.get("base_url", "http://localhost:11434")).rstrip("/"),
            model=str(data.get("model", "llama3.2:3b")),
            timeout_sec=float(data.get("timeout_sec", 30.0)),
        )


@dataclass
class Settings:
    """Fully-resolved runtime settings."""

    project_root: Path
    mappings_dir: Path
    output_dir: Path
    errors_dir: Path
    runs_dir: Path
    state_dir: Path
    postgres: PostgresSettings = field(default_factory=PostgresSettings)
    kafka: KafkaSettings = field(default_factory=KafkaSettings)
    analysis: AnalysisSettings = field(default_factory=AnalysisSettings)
    rag: RagSettings = field(default_factory=RagSettings)
    ollama: OllamaSettings = field(default_factory=OllamaSettings)
    dedup_enabled: bool = True
    dedup_window_minutes: int = 60
    dedup_persist: bool = True
    log_level: str = "INFO"
    log_format: str = DEFAULT_LOG_FORMAT
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], project_root: Path) -> "Settings":
        try:
            paths = data.get("paths") or {}
            pipeline = data.get("pipeline") or {}
            dedup = pipeline.get("deduplication") or {}
            logging_cfg = data.get("logging") or {}
            postgres_cfg = data.get("postgres") or {}
            kafka_cfg = data.get("kafka") or {}
            analysis_cfg = data.get("analysis") or {}
            rag_cfg = data.get("rag") or {}
            ollama_cfg = data.get("ollama") or {}
        except AttributeError as exc:  # non-mapping input
            raise ConfigError(f"Invalid settings structure: {exc}") from exc

        root = project_root
        return cls(
            project_root=root,
            mappings_dir=_rooted(root, paths.get("mappings_dir", "config/mappings")),
            output_dir=_rooted(root, paths.get("output_dir", "data/output")),
            errors_dir=_rooted(root, paths.get("errors_dir", "data/output/_errors")),
            runs_dir=_rooted(root, paths.get("runs_dir", "data/output/_runs")),
            state_dir=_rooted(root, paths.get("state_dir", "data/state")),
            postgres=PostgresSettings.from_mapping(postgres_cfg),
            kafka=KafkaSettings.from_mapping(kafka_cfg),
            analysis=AnalysisSettings.from_mapping(analysis_cfg),
            rag=RagSettings.from_mapping(rag_cfg, project_root),
            ollama=OllamaSettings.from_mapping(ollama_cfg),
            dedup_enabled=to_bool(dedup.get("enabled", True)),
            dedup_window_minutes=int(dedup.get("window_minutes", 60)),
            dedup_persist=to_bool(dedup.get("persist", True)),
            log_level=str(logging_cfg.get("level", "INFO")).upper(),
            log_format=str(logging_cfg.get("format", DEFAULT_LOG_FORMAT)),
            extra={
                k: v
                for k, v in data.items()
                if k not in {"paths", "pipeline", "logging", "postgres"}
            },
        )

    @property
    def dedup_state_file(self) -> Path:
        return self.state_dir / "dedup_state.json"

    @property
    def db_schema_file(self) -> Path:
        return self.project_root / "db" / "schema.sql"

    @property
    def correlation_rules_file(self) -> Path:
        return self.project_root / "config" / "correlation_rules.yml"

    def ensure_directories(self) -> None:
        for d in (self.output_dir, self.errors_dir, self.runs_dir, self.state_dir):
            d.mkdir(parents=True, exist_ok=True)


def load_settings(config_path: str | Path | None = None) -> Settings:
    """Load settings from YAML, raising a clear ConfigError on any problem."""
    root = default_project_root()
    path = Path(config_path) if config_path else root / "config" / "settings.yml"
    if not path.is_file():
        raise ConfigError(f"settings file not found: {path}")

    # .env is optional; real environment variables win (handled inside load_dotenv)
    load_dotenv(path.resolve().parents[1] / ".env")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in settings file {path}: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ConfigError(f"settings file {path} must contain a YAML mapping")

    return Settings.from_dict(expand_env(data), path.resolve().parents[1])


def configure_logging(settings: Settings, level_override: str | None = None) -> None:
    level = (level_override or settings.log_level).upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format=settings.log_format,
        force=True,
    )
