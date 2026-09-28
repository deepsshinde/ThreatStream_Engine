"""MITRE ATT&CK technique loading.

Two modes:

* **STIX mode** - parses the official Enterprise ATT&CK STIX 2.1 bundle
  (from ``mitre-attack/attack-stix-data`` on GitHub), extracting technique
  ID, name, description, tactics and detection guidance for every current
  ``attack-pattern`` (sub-techniques included, revoked/deprecated excluded).
* **Builtin mode** - loads ``data/mitre/builtin_techniques.json``, a curated
  ~14-technique seed covering this project's detections. Guarantees the RAG
  layer works fully offline / in air-gapped demos - honestly smaller, and
  labelled as such.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.exceptions import ThreatStreamError

logger = logging.getLogger("threatstream.mitre.loader")

DEFAULT_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


@dataclass
class Technique:
    id: str
    name: str
    description: str
    tactics: list[str] = field(default_factory=list)
    detection: str = ""
    url: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def text_for_embedding(self) -> str:
        return (
            f"MITRE ATT&CK {self.id} {self.name}. {self.description} "
            f"Tactics: {', '.join(self.tactics)}. Detection guidance: {self.detection}"
        )


def load_builtin(path: str | Path) -> list[Technique]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    techniques = [Technique(**{k: t.get(k, [] if k == "tactics" else "") for k in ("id", "name", "description", "tactics", "detection", "url")}) for t in data]
    logger.info("Loaded %d builtin techniques from %s", len(techniques), path)
    return techniques


def parse_stix_bundle(bundle: dict) -> list[Technique]:
    """Parse a STIX 2.1 ATT&CK bundle into Technique objects (pure stdlib json)."""
    techniques: list[Technique] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        refs = obj.get("external_references") or []
        attack_ref = next(
            (r for r in refs if r.get("source_name") in {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}),
            None,
        )
        if not attack_ref or not str(attack_ref.get("external_id", "")).startswith("T"):
            continue
        tactics = [
            str(p.get("phase_name", ""))
            for p in obj.get("kill_chain_phases", [])
            if p.get("phase_name")
        ]
        techniques.append(
            Technique(
                id=str(attack_ref["external_id"]),
                name=str(obj.get("name", "")),
                description=str(obj.get("description", "")),
                tactics=tactics,
                detection=str(obj.get("x_mitre_detection", "")),
                url=str(attack_ref.get("url", "")),
            )
        )
    logger.info("Parsed %d techniques from STIX bundle", len(techniques))
    return techniques


def fetch_stix_bundle(url: str = DEFAULT_STIX_URL, timeout: float = 60.0) -> dict:
    """Download the official Enterprise ATT&CK STIX bundle (~60 MB JSON)."""
    logger.info("Downloading MITRE ATT&CK STIX from %s ...", url)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        raise ThreatStreamError(f"failed to download MITRE STIX data from {url}: {exc}") from exc


def load_techniques(
    source: str = "auto",
    stix_url: str = DEFAULT_STIX_URL,
    stix_file: str | Path | None = None,
    builtin_file: str | Path | None = None,
) -> tuple[list[Technique], str]:
    """Returns (techniques, source_description).

    source: "stix" | "builtin" | "auto" (stix -> builtin fallback with warning).
    """
    if source not in {"stix", "builtin", "auto"}:
        raise ThreatStreamError(f"unknown MITRE source '{source}'")

    if source in {"stix", "auto"}:
        try:
            if stix_file:
                bundle = json.loads(Path(stix_file).read_text(encoding="utf-8"))
                techniques = parse_stix_bundle(bundle)
                return techniques, f"stix-file:{stix_file}"
            bundle = fetch_stix_bundle(stix_url)
            techniques = parse_stix_bundle(bundle)
            return techniques, f"stix:{stix_url}"
        except ThreatStreamError as exc:
            if source == "stix":
                raise
            logger.warning("STIX unavailable (%s); falling back to builtin subset", exc)

    if not builtin_file or not Path(builtin_file).is_file():
        raise ThreatStreamError(f"builtin techniques file not found: {builtin_file}")
    techniques = load_builtin(builtin_file)
    return techniques, f"builtin:{builtin_file}"
