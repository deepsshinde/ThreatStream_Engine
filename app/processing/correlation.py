"""Reusable multi-event correlation engine.

Rules are YAML (``config/correlation_rules.yml``), not code. The engine keeps
a sliding per-(rule, group_key) window of matching normalized events and
emits a :class:`SecuritySignal` when the rule's ordered steps are satisfied.

The same engine instance works in **streaming** mode (consumer feeds events
one-by-one, signals fire as soon as a window completes) and **batch** mode
(feed a list from storage, e.g. the CLI ``correlate`` command).

Semantics of the two rule shapes we actually use (kept deliberately small):

* **Threshold**            - one step with ``min_count`` (optionally + a
                             ``distinct`` path with ``min_distinct``).
* **Sequence**             - ordered steps; step N matches only events *after*
                             the first event of step N-1's match window.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Iterable, Mapping

import yaml

from app.exceptions import ConfigError
from app.mapping.resolver import get_path
from app.schemas.findings import SecuritySignal, TechniqueReference

logger = logging.getLogger("threatstream.correlation")


@dataclass(frozen=True)
class Step:
    name: str
    filter: dict[str, str]
    min_count: int = 1
    distinct: str | None = None
    min_distinct: int = 0


@dataclass(frozen=True)
class CorrelationRule:
    id: str
    description: str
    severity: str
    risk_score: int
    mitre_techniques: tuple[TechniqueReference, ...]
    group_by: tuple[str, ...]
    window_seconds: int
    steps: tuple[Step, ...]


def load_rules(path: str | Path) -> list[CorrelationRule]:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"correlation rules file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in correlation rules {path}: {exc}") from exc
    if not isinstance(data, Mapping) or not isinstance(data.get("rules"), list):
        raise ConfigError(f"correlation rules {path} must contain a 'rules' list")

    rules: list[CorrelationRule] = []
    for raw in data["rules"]:
        try:
            steps = tuple(
                Step(
                    name=str(s.get("name", f"step-{i}")),
                    filter={str(k): str(v) for k, v in (s.get("filter") or {}).items()},
                    min_count=int(s.get("min_count", 1)),
                    distinct=s.get("distinct"),
                    min_distinct=int(s.get("min_distinct", 0)),
                )
                for i, s in enumerate(raw["steps"])
            )
            techniques = tuple(TechniqueReference(**t) for t in raw.get("mitre_techniques", []))
            rules.append(
                CorrelationRule(
                    id=str(raw["id"]),
                    description=str(raw.get("description", raw["id"])),
                    severity=str(raw.get("severity", "Medium")),
                    risk_score=int(raw.get("risk_score", 40)),
                    mitre_techniques=techniques,
                    group_by=tuple(str(g) for g in raw["group_by"]),
                    window_seconds=int(float(raw.get("window_minutes", 10)) * 60),
                    steps=steps,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigError(f"invalid correlation rule {raw!r}: {exc}") from exc
    return rules


def _matches(event: Mapping[str, Any], step_filter: Mapping[str, str]) -> bool:
    for path, expected in step_filter.items():
        value = get_path(event, path)
        if value is None or str(value) != expected:
            return False
    return True


def _event_time(event: Mapping[str, Any]) -> int:
    try:
        return int(event.get("time", 0)) // 1000  # ms -> seconds
    except (TypeError, ValueError):
        return 0


def _event_uid(event: Mapping[str, Any]) -> str:
    return str((event.get("metadata") or {}).get("uid", ""))


class CorrelationEngine:
    def __init__(self, rules: list[CorrelationRule]):
        self.rules = rules
        # (rule_id, group_key) -> deque[(epoch_sec, event)]
        self._windows: dict[tuple[str, tuple[str, ...]], Deque[tuple[int, Mapping[str, Any]]]] = defaultdict(deque)
        # (rule_id, group_key) -> last time a signal fired (suppression)
        self._fired_at: dict[tuple[str, tuple[str, ...]], int] = {}

    # ------------------------------------------------------------------ #
    def process(self, events: Iterable[Mapping[str, Any]]) -> list[SecuritySignal]:
        signals: list[SecuritySignal] = []
        for event in sorted(events, key=_event_time):
            signal = self.ingest(event)
            if signal is not None:
                signals.append(signal)
        return signals

    def ingest(self, event: Mapping[str, Any]) -> SecuritySignal | None:
        """Feed one normalized event; returns a signal if one just fired."""
        for rule in self.rules:
            if not any(_matches(event, step.filter) for step in rule.steps):
                continue
            group = self._group_key(rule, event)
            if group is None:
                continue
            window = self._windows[(rule.id, group)]
            window.append((_event_time(event), event))
            self._prune(rule, window)

            if self._evaluate(rule, window) is None:
                continue
            now = _event_time(event)
            if now - self._fired_at.get((rule.id, group), -10**9) < rule.window_seconds:
                continue  # already reported for this window
            self._fired_at[(rule.id, group)] = now
            return self._make_signal(rule, group, window)
        return None

    # ------------------------------------------------------------------ #
    def _group_key(self, rule: CorrelationRule, event: Mapping[str, Any]) -> tuple[str, ...] | None:
        parts = []
        for path in rule.group_by:
            value = get_path(event, path)
            if value is None or str(value) in {"", "-"}:
                return None  # cannot correlate without a stable identity
            parts.append(str(value))
        return tuple(parts)

    @staticmethod
    def _prune(rule: CorrelationRule, window: Deque[tuple[int, Mapping[str, Any]]]) -> None:
        latest = window[-1][0]
        cutoff = latest - rule.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

    def _evaluate(self, rule: CorrelationRule, window: Deque[tuple[int, Mapping[str, Any]]]) -> list[Mapping[str, Any]] | None:
        after = -1  # seconds; -1 = no constraint yet
        matched_all: list[Mapping[str, Any]] = []
        for step in rule.steps:
            events = [ev for ts, ev in window if ts > after and _matches(ev, step.filter)]
            if len(events) < step.min_count:
                return None
            if step.distinct:
                distinct = {str(get_path(ev, step.distinct)) for ev in events if get_path(ev, step.distinct) is not None}
                if len(distinct) < step.min_distinct:
                    return None
            matched_all.extend(events)
            after = min(_event_time(ev) for ev in events)  # next step must be later
        return matched_all

    def _make_signal(
        self,
        rule: CorrelationRule,
        group: tuple[str, ...],
        window: Deque[tuple[int, Mapping[str, Any]]],
    ) -> SecuritySignal:
        matched = self._evaluate(rule, window) or []
        first = min((_event_time(ev) for ev in matched), default=0)
        last = max((_event_time(ev) for ev in matched), default=0)
        group_key = {field: value for field, value in zip(rule.group_by, group)}
        seed = f"{rule.id}|{first}|{'|'.join(group)}"
        signal_id = hashlib.sha256(seed.encode()).hexdigest()[:24]
        signal = SecuritySignal(
            signal_id=signal_id,
            rule_id=rule.id,
            severity=rule.severity,
            description=rule.description,
            risk_score=rule.risk_score,
            mitre_techniques=list(rule.mitre_techniques),
            group_key=group_key,
            event_uids=[_event_uid(ev) for ev in matched if _event_uid(ev)][:50],
            first_seen=first * 1000,
            last_seen=last * 1000,
        )
        logger.warning("SIGNAL %s (%s) key=%s events=%d", rule.id, rule.severity, group_key, len(matched))
        return signal
