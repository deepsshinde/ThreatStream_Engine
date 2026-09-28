"""Value resolution for the YAML mapping engine.

Supports the five mapping constructs the platform promises:

1. **Static values**      - anything that is not a template string is passed through.
2. **Templates**          - ``"{userIdentity.userName}"`` pulls a nested value out of
   the raw event with dot-path syntax (list indexes allowed: ``a.0.b``).
   ``"{pathA|pathB}"`` tries fallbacks left-to-right.
3. **Mixed templates**    - ``"user {name} logged in from {ip}"`` interpolates text.
4. **Enums**              - evaluate an expression, match a value table, else ``other``.
5. **Wildcards**          - activity maps support fnmatch patterns (``Create*``).

Plus :func:`to_epoch_ms`, the single place where every timestamp flavor
(ISO-8601 strings, epoch seconds, epoch milliseconds, datetime objects,
custom format strings) is normalized to the OCSF ``time`` integer.
"""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime, timezone
from typing import Any, Mapping

MISSING = None
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")

# Epoch-millisecond sanity window: 2000-01-01 .. 2100-01-01
MIN_PLAUSIBLE_TIME_MS = 946_684_800_000
MAX_PLAUSIBLE_TIME_MS = 4_102_444_800_000
# Above this an integer is treated as already being milliseconds
_EPOCH_SEC_MS_CUTOVER = 1e11


def get_path(event: Any, path: str) -> Any:
    """Resolve a dot-separated path against dicts/lists. Returns None if missing."""
    current: Any = event
    if not path:
        return None
    for part in path.split("."):
        if isinstance(current, Mapping):
            if part not in current:
                return None
            current = current[part]
        elif isinstance(current, (list, tuple)):
            if not part.isdigit() or int(part) >= len(current):
                return None
            current = current[int(part)]
        else:
            return None
    return current


def _resolve_placeholder(expr: str, event: Mapping[str, Any]) -> Any:
    """Resolve one ``{...}`` expression; ``|`` separates fallback paths."""
    for candidate in expr.split("|"):
        candidate = candidate.strip()
        if not candidate:
            continue
        value = get_path(event, candidate)
        if value is not None:
            return value
    return None


def resolve_template(template: Any, event: Mapping[str, Any]) -> Any:
    """Resolve static values, full placeholders and mixed templates.

    * Non-string input        -> returned unchanged (static value).
    * ``"{path}"`` (whole)    -> raw value (type preserved).
    * ``"text {path} text"``  -> string interpolation (missing -> empty).
    """
    if not isinstance(template, str):
        return template
    stripped = template.strip()
    full = _PLACEHOLDER_RE.fullmatch(stripped)
    if full is not None:
        return _resolve_placeholder(full.group(1), event)

    def _sub(match: re.Match[str]) -> str:
        value = _resolve_placeholder(match.group(1), event)
        return "" if value is None else str(value)

    return _PLACEHOLDER_RE.sub(_sub, template)


def resolve_enum(spec: Mapping[str, Any], event: Mapping[str, Any]) -> Any:
    """Resolve an ``enum:`` node.

    ``evaluate`` is a template; the result is matched against ``values``
    (a ``null`` YAML key matches a missing evaluated value); if nothing
    matches, ``other`` is returned.
    """
    if not isinstance(spec, Mapping):
        return spec
    evaluated = resolve_template(spec.get("evaluate"), event)
    values = spec.get("values") or {}

    if evaluated is None:
        candidates: list[Any] = [None, "null", ""]
    else:
        candidates = [evaluated, str(evaluated)]
    for candidate in candidates:
        try:
            if candidate in values:
                return values[candidate]
        except TypeError:  # unhashable candidate (list/dict values)
            continue
    return spec.get("other")


def match_pattern_map(
    value: Any,
    pattern_map: Mapping[Any, Any],
    default: Any = None,
) -> Any:
    """Match ``value`` against an ordered map of exact keys / fnmatch wildcards.

    Exact (type-preserving) matches win first, then string wildcard patterns
    in mapping order, then ``default``.
    """
    if value is None or not pattern_map:
        return default
    try:
        if value in pattern_map:
            return pattern_map[value]
    except TypeError:
        pass
    text = str(value)
    for pattern, entry in pattern_map.items():
        if isinstance(pattern, str) and any(ch in pattern for ch in "*?[") and fnmatch.fnmatchcase(text, pattern):
            return entry
    return default


def to_epoch_ms(value: Any, format: str | None = None) -> int:
    """Normalize any supported timestamp flavor to epoch milliseconds.

    Raises ValueError for values that cannot be interpreted as a timestamp.
    """
    if value is None:
        raise ValueError("missing timestamp value")

    if isinstance(value, bool):  # bool is an int subclass - reject explicitly
        raise ValueError(f"invalid timestamp value: {value!r}")

    if isinstance(value, (int, float)):
        number = float(value)
        # Heuristic: ~seconds since 2001. Above 1e11 it's already milliseconds.
        millis = number if number >= _EPOCH_SEC_MS_CUTOVER else number * 1000
        return int(millis)

    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)

    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty timestamp string")
        if format:
            dt = datetime.strptime(text, format).replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        if re.fullmatch(r"\d+(\.\d+)?", text):
            return to_epoch_ms(float(text))
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"unparseable timestamp: {text!r}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)

    raise ValueError(f"unsupported timestamp type: {type(value).__name__}")
