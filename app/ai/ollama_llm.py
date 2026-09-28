"""Ollama-backed local LLM engine.

Talks to a local Ollama server over plain HTTP (stdlib :mod:`urllib` - no new
dependency). Everything about this engine is *optional*: if Ollama is not
running, :func:`is_available` is False and the analyzer uses the fallback.

The engine insists on structured output (Ollama's ``format: json`` hint) and
then validates it strictly with Pydantic. Bad JSON, wrong schema, timeouts,
HTTP 5xx -> typed exceptions the caller degrades from gracefully.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request

from pydantic import ValidationError

from app.ai.base import AnalysisRequest, LLMParseError, LLMUnavailable
from app.ai.prompts import build_prompt
from app.schemas.findings import LLMAnalysis

logger = logging.getLogger("threatstream.ai.ollama")

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


class OllamaLLM:
    name = "ollama"

    def __init__(self, base_url: str, model: str, timeout_sec: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout_sec
        self._availability: bool | None = None

    # ------------------------------------------------------------------ #
    def is_available(self) -> bool:
        if self._availability is not None:
            return self._availability
        try:
            with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=2.5) as resp:
                data = json.loads(resp.read().decode())
            models = {m.get("name") for m in data.get("models", [])}
            if any(self.model == m or self.model.startswith(f"{m}:") or m.startswith(f"{self.model}:") for m in models):
                self._availability = True
            else:
                logger.info("Ollama is up at %s but model '%s' is not pulled (have: %s)", self.base_url, self.model, models)
                self._availability = False
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            self._availability = False
        return self._availability

    def reset_availability_cache(self) -> None:
        self._availability = None

    # ------------------------------------------------------------------ #
    def analyze(self, request: AnalysisRequest) -> LLMAnalysis:
        if not self.is_available():
            raise LLMUnavailable(
                f"Ollama not available at {self.base_url} (model={self.model}). "
                f"Install: https://ollama.com, then: ollama pull {self.model}"
            )
        prompt = build_prompt(request)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
        }
        body = json.dumps(payload).encode("utf-8")
        http = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(http, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise LLMUnavailable(f"Ollama request failed: {exc}") from exc

        raw = str(data.get("response", ""))
        logger.info("Ollama response received (%d chars)", len(raw))
        return self.parse_response(raw)

    # ------------------------------------------------------------------ #
    @staticmethod
    def parse_response(raw: str) -> LLMAnalysis:
        """Extract + validate the JSON object from raw LLM output."""
        text = raw.strip()
        text = re.sub(r"^```(json)?|```$", "", text, flags=re.MULTILINE).strip()
        match = _JSON_BLOCK_RE.search(text)
        if not match:
            raise LLMParseError(f"no JSON object found in LLM output: {raw[:200]!r}")
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise LLMParseError(f"invalid JSON from LLM: {exc}") from exc
        try:
            return LLMAnalysis.model_validate(data)
        except ValidationError as exc:
            raise LLMParseError(f"LLM output failed schema validation: {exc}") from exc
