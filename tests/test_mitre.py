import json

import numpy as np
import pytest

from app.mitre.embeddings import HashingVectorBackend, get_backend
from app.mitre.loader import Technique, load_builtin, load_techniques, parse_stix_bundle
from app.mitre.vector_store import TechniqueVectorStore


@pytest.fixture
def builtin_file(project_root):
    return project_root / "data" / "mitre" / "builtin_techniques.json"


class TestBuiltinSeed:
    def test_builtin_techniques_valid(self, builtin_file):
        techniques = load_builtin(builtin_file)
        assert len(techniques) >= 12
        for t in techniques:
            assert t.id.startswith("T") and t.id[1:].replace(".", "").isdigit()
            assert t.name and t.description and t.tactics

    def test_embedding_text_not_empty(self, builtin_file):
        t = load_builtin(builtin_file)[0]
        assert "T1110" in t.text_for_embedding()
        assert "Detection guidance" in t.text_for_embedding()


class TestStixParser:
    BUNDLE = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Brute Force",
                "description": "Adversaries may use brute force...",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
                "x_mitre_detection": "Monitor authentication logs.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1110", "url": "https://attack.mitre.org/techniques/T1110/"}
                ],
            },
            {
                "type": "attack-pattern",
                "name": "Old Thing",
                "revoked": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
            },
            {"type": "malware", "name": "NotATechnique"},
            {
                "type": "attack-pattern",
                "name": "Deprecated X",
                "x_mitre_deprecated": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T0002"}],
            },
        ],
    }

    def test_parses_only_current_attack_patterns(self):
        techniques = parse_stix_bundle(self.BUNDLE)
        assert len(techniques) == 1
        t = techniques[0]
        assert t.id == "T1110"
        assert t.tactics == ["credential-access"]
        assert "authentication" in t.detection
        assert t.url.endswith("/T1110/")

    def test_load_techniques_builtin_mode(self, builtin_file):
        techniques, desc = load_techniques(source="builtin", builtin_file=builtin_file)
        assert desc.startswith("builtin:")
        assert len(techniques) >= 12

    def test_load_techniques_auto_falls_back_when_stix_unreachable(self, builtin_file, monkeypatch):
        from app.mitre import loader

        def _boom(*a, **kw):
            from app.exceptions import ThreatStreamError

            raise ThreatStreamError("no network")

        monkeypatch.setattr(loader, "fetch_stix_bundle", _boom)
        techniques, desc = load_techniques(source="auto", builtin_file=builtin_file)
        assert desc.startswith("builtin:")


class TestHashingBackend:
    def test_deterministic_and_normalized(self):
        backend = HashingVectorBackend(dim=64)
        v1 = backend.embed(["failed logon brute force attempt"])
        v2 = backend.embed(["failed logon brute force attempt"])
        assert np.allclose(v1, v2)
        assert np.isclose(np.linalg.norm(v1[0]), 1.0)
        assert v1.shape == (1, 64)

    def test_empty_text_does_not_crash(self):
        v = HashingVectorBackend().embed([""])
        assert v.shape == (1, 256)


class TestVectorStore:
    TOYS = [
        Technique(id="T1110", name="Brute Force", description="guess passwords repeatedly until access is gained", tactics=["credential-access"], detection="failed logons"),
        Technique(id="T1046", name="Network Service Discovery", description="scan many destination ports to find services", tactics=["discovery"], detection="refused connections"),
        Technique(id="T1071", name="Web Protocols", description="command and control over http web traffic", tactics=["command-and-control"], detection="proxy logs"),
    ]

    def _store(self):
        return TechniqueVectorStore.build(self.TOYS, HashingVectorBackend(dim=128), source="test")

    def test_search_returns_best_match(self):
        store = self._store()
        results = store.search("repeated failed logons password guessing attack", top_k=2)
        assert results[0][0].id == "T1110"
        results = store.search("attacker scanning open ports on hosts", top_k=2)
        assert results[0][0].id == "T1046"

    def test_threshold_filters_weak_matches(self):
        store = self._store()
        results = store.search("xyzzy completely unrelated gibberish zork", top_k=3, threshold=0.95)
        assert results == []

    def test_empty_store(self):
        store = TechniqueVectorStore(HashingVectorBackend(), np.zeros((0, 256), dtype=np.float32), [], "test")
        assert store.search("anything", top_k=3) == []

    def test_save_load_roundtrip(self, tmp_path):
        self._store().save(tmp_path)
        assert TechniqueVectorStore.is_available(tmp_path)
        loaded = TechniqueVectorStore.load(tmp_path)
        assert loaded.backend.name == "hashing"
        results = loaded.search("password brute force failed logon burst", top_k=1)
        assert results[0][0].id == "T1110"
        metadata = json.loads((tmp_path / "metadata.json").read_text())
        assert metadata["count"] == 3
        assert metadata["dim"] == 128

    def test_missing_index_raises_actionable_error(self, tmp_path):
        from app.exceptions import ThreatStreamError

        with pytest.raises(ThreatStreamError, match="build-mitre-index"):
            TechniqueVectorStore.load(tmp_path / "nope")

    def test_get_backend_rejects_unknown(self):
        with pytest.raises(ValueError):
            get_backend("quantum-embedder")
