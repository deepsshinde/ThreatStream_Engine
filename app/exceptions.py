"""Domain exceptions for ThreatStream Engine.

Every pipeline stage raises a *specific, catchable* exception so the pipeline
can isolate a single bad event (or a single bad config file) without crashing
the whole run.
"""


class ThreatStreamError(Exception):
    """Base class for all ThreatStream errors."""


class ConfigError(ThreatStreamError):
    """Raised when settings.yml or a YAML mapping file is invalid/unreadable."""


class PostgresUnavailable(ThreatStreamError):
    """Raised when PostgreSQL is unreachable or the driver is missing.

    The pipeline treats this as *degraded mode*, not a crash: file storage
    keeps working and the run summary notes the DB was skipped.
    """


class IngestionError(ThreatStreamError):
    """Raised when a raw log file cannot be parsed at all."""


class MappingError(ThreatStreamError):
    """Raised when a raw event cannot be mapped to an OCSF event."""


class KafkaUnavailable(ThreatStreamError):
    """Raised when kafka-python is missing or the broker is unreachable.

    Same ethos as PostgresUnavailable: the pipeline must degrade/explain,
    never stack-trace on a missing optional service.
    """
