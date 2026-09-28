"""Content-based deduplication with a configurable time window.

Every normalized event gets a deterministic fingerprint::

    SHA256( canonical_json(event, excluding volatile metadata) )

Design decision (worth being explicit about in an interview):

* The fingerprint **includes the event timestamp** and all mapped content.
  Two ConsoleLogins for the same user five minutes apart are *distinct
  security events*, not duplicates - deduplication must never drop them.
  Dedup exists to protect the pipeline from **at-least-once redelivery**:
  the same Kafka message consumed twice, the same file ingested twice, a
  publisher retrying. Those copies arrive with byte-identical content.
* Volatile fields (``metadata.uid``, ``metadata.logged_time``) are excluded
  so re-ingesting the same *content* still yields the same fingerprint -
  which is also what makes downstream storage idempotent (the fingerprint
  becomes ``metadata.uid``).
* The window (default 60 minutes) is the TTL of the dedup memory, measured
  in *processing time*: if the same fingerprint was accepted within the
  window it is a duplicate; older fingerprints are forgotten so memory and
  disk state stay bounded on long-running consumers.
* State can be persisted to disk so separate CLI runs deduplicate against
  each other.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Mapping

logger = logging.getLogger("threatstream.dedup")

_VOLATILE_METADATA_KEYS = ("uid", "logged_time")


class Deduplicator:
    def __init__(
        self,
        window_minutes: int = 60,
        enabled: bool = True,
        state_path: str | Path | None = None,
    ):
        self.enabled = enabled
        self.window_ms = int(window_minutes) * 60 * 1000
        self.state_path = Path(state_path) if state_path else None
        self._seen: dict[str, int] = {}  # fingerprint -> processing time (ms) last accepted
        if self.enabled and self.state_path:
            self._load()

    # ------------------------------------------------------------------ #
    @staticmethod
    def fingerprint(event: Mapping[str, Any]) -> str:
        """Deterministic content hash over the event, excluding volatile fields."""
        payload: dict[str, Any] = {}
        for key, value in event.items():
            if key == "metadata" and isinstance(value, Mapping):
                payload[key] = {
                    k: v for k, v in value.items() if k not in _VOLATILE_METADATA_KEYS
                }
            else:
                payload[key] = value
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ #
    def is_duplicate(self, event: Mapping[str, Any]) -> tuple[bool, str]:
        """Returns (is_duplicate, fingerprint)."""
        fp = self.fingerprint(event)
        if not self.enabled:
            return False, fp

        now = int(time.time() * 1000)
        last_seen = self._seen.get(fp)
        if last_seen is not None and (now - last_seen) <= self.window_ms:
            return True, fp

        self._seen[fp] = now
        return False, fp

    # ------------------------------------------------------------------ #
    def close(self) -> None:
        if self.enabled and self.state_path:
            self._save()

    def _load(self) -> None:
        if not self.state_path or not self.state_path.is_file():
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read dedup state %s (%s); starting fresh", self.state_path, exc)
            return
        if isinstance(data, dict):
            self._seen = {str(k): int(v) for k, v in data.items()}
            logger.debug("Loaded %d dedup fingerprints from %s", len(self._seen), self.state_path)

    def _save(self) -> None:
        if not self.state_path:
            return
        # Forget fingerprints older than 2x the window - they can no longer
        # affect duplicate decisions, so memory/disk stay bounded.
        cutoff = int(time.time() * 1000) - 2 * self.window_ms
        self._seen = {fp: ts for fp, ts in self._seen.items() if ts >= cutoff}
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._seen), encoding="utf-8")
            tmp.replace(self.state_path)
        except OSError as exc:
            logger.warning("Could not persist dedup state %s: %s", self.state_path, exc)
