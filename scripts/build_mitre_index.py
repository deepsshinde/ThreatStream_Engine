#!/usr/bin/env python3
"""Build the MITRE ATT&CK vector index for the RAG layer.

    python scripts/build_mitre_index.py                      # auto (STIX if reachable)
    python scripts/build_mitre_index.py --source builtin     # offline demo data
    python scripts/build_mitre_index.py --embedder hashing   # zero-dependency vectors
    python scripts/build_mitre_index.py --stix-file enterprise-attack.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import configure_logging, load_settings
from app.exceptions import ThreatStreamError
from app.mitre.index_builder import build_mitre_index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=["auto", "stix", "builtin"], default="auto")
    parser.add_argument("--embedder", choices=["auto", "sentence-transformers", "hashing"], default=None)
    parser.add_argument("--stix-file", default=None, help="Path to a local enterprise-attack.json")
    parser.add_argument("--config", default=None, help="Path to settings.yml")
    args = parser.parse_args()

    try:
        settings = load_settings(args.config)
        configure_logging(settings)
        result = build_mitre_index(
            settings, source=args.source, embedder_name=args.embedder, stix_file=args.stix_file
        )
    except ThreatStreamError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        f"MITRE index built: {result['techniques']} techniques "
        f"(source={result['source']}, embedder={result['embedder_backend']} "
        f"dim={result['dim']}) in {result['duration_sec']}s -> {result['data_dir']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
