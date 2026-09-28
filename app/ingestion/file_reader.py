"""File ingestion.

Reads raw security logs from disk and yields :class:`RawRecord` objects.
Supported shapes:

* JSON array of events:            ``[{...}, {...}]``
* Object wrapping an event array:  ``{"Records": [...]}`` (CloudTrail export style)
* Single JSON object:              ``{...}``
* Newline-delimited JSON (NDJSON): one event per line

Malformed input never raises into the pipeline: a JSON file that does not
parse as a whole is retried line-by-line, and each broken line is yielded as
an ingestion-stage error record so it is counted and stored as a failure.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("threatstream.ingestion.files")


@dataclass
class RawRecord:
    """One raw observation from a source: either an event or an ingestion error."""

    source_file: str
    line: int | None = None
    event: dict[str, Any] | None = None
    error: str | None = None
    raw_text: str | None = None


def _ok(event: dict[str, Any], source_file: Path, line: int | None = None) -> RawRecord:
    return RawRecord(source_file=str(source_file), line=line, event=event)


def _bad(source_file: Path, error: str, raw_text: str, line: int | None = None) -> RawRecord:
    return RawRecord(source_file=str(source_file), line=line, error=error, raw_text=raw_text)


def iter_file_events(path: str | Path) -> Iterator[RawRecord]:
    """Yield RawRecords from a single log file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        yield _bad(path, f"unreadable file: {exc}", raw_text="")
        return

    stripped = text.strip()
    if not stripped:
        yield _bad(path, "empty file", raw_text="")
        return

    # First try the whole-document shapes.
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        parsed = None

    if parsed is not None:
        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, dict):
                    yield _ok(item, path)
                else:
                    yield _bad(path, f"array element is not a JSON object: {type(item).__name__}", json.dumps(item, default=str)[:500])
        elif isinstance(parsed, dict):
            records = parsed.get("Records")
            if isinstance(records, list):
                for item in records:
                    if isinstance(item, dict):
                        yield _ok(item, path)
                    else:
                        yield _bad(path, f"Records element is not a JSON object: {type(item).__name__}", json.dumps(item, default=str)[:500])
            else:
                yield _ok(parsed, path)
        else:
            yield _bad(path, f"top-level JSON must be object or array, got {type(parsed).__name__}", stripped[:500])
        return

    # Fall back to NDJSON: one event per line.
    for lineno, line in enumerate(stripped.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            yield _bad(path, f"malformed JSON: {exc.msg}", raw_text=line[:500], line=lineno)
            continue
        if isinstance(item, dict):
            yield _ok(item, path, line=lineno)
        else:
            yield _bad(path, f"line is not a JSON object: {type(item).__name__}", raw_text=line[:500], line=lineno)


def iter_directory_events(directory: str | Path, pattern: str = "*.json") -> Iterator[RawRecord]:
    """Yield RawRecords for every matching top-level file in a directory."""
    directory = Path(directory)
    if not directory.is_dir():
        yield _bad(directory, f"directory not found: {directory}", raw_text="")
        return

    files = sorted(p for p in directory.iterdir() if p.is_file() and not p.name.startswith("_"))
    if pattern != "*.json":
        files = [p for p in files if p.match(pattern)]
    else:
        files = [p for p in files if p.suffix.lower() in {".json", ".jsonl"}]
    if not files:
        yield _bad(directory, f"no matching log files in {directory}", raw_text="")
        return
    for path in files:
        logger.info("Reading log file %s", path)
        yield from iter_file_events(path)
