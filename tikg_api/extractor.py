"""
ThreatExtractor - NER + relation extraction pipeline.
Based on the TiKG framework (github.com/imouiche/Threat-Intelligence-Knowledge-Graphs).

Entity types aligned with STIX 2.1 threat intel vocabulary:
  - malware      : malware families and samples
  - actor        : threat actors / APT groups
  - tool         : offensive tools and utilities
  - vulnerability: CVEs and weakness identifiers
  - tactic       : ATT&CK tactics
  - indicator    : IPs, domains, hashes
"""

import logging
import re
from typing import Any

import networkx as nx

log = logging.getLogger(__name__)

# Regex patterns for high-confidence indicators (fast path, no model required)
_INDICATOR_PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|gov|edu|ru|cn|de|uk)\b"
    ),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
}


class ThreatExtractor:
    """
    Two-stage pipeline:
    1. Fast regex pass for high-confidence indicators (IPs, CVEs, hashes, URLs).
    2. Transformer-based NER for semantic entities (malware, actors, tools, tactics).
    """

    def __init__(self, model_name: str = "secureBERT"):
        self.model_name = model_name
        self._nlp = None
        self._ner = None
        self._load_models()

    def _load_models(self):
        try:
            from transformers import pipeline as hf_pipeline

            log.info("Loading transformer NER pipeline (%s)…", self.model_name)
            # Use a cybersecurity-aware NER model if available, else fall back to
            # a generic English NER model (still useful for actor/tool detection).
            model_id = (
                "jackaduma/SecRoBERTa"
                if self.model_name.lower() in ("securebert", "secroberta")
                else "dslim/bert-base-NER"
            )
            self._ner = hf_pipeline(
                "ner",
                model=model_id,
                aggregation_strategy="simple",
                device=-1,  # CPU; change to 0 for GPU
            )
            log.info("NER pipeline loaded: %s", model_id)
        except Exception as exc:  # noqa: BLE001
            log.warning("Transformer NER unavailable (%s); using regex-only mode.", exc)
            self._ner = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, text: str) -> dict[str, Any]:
        entities = self._extract_entities(text)
        relations = self._extract_relations(entities, text)
        graph = self._build_graph(entities, relations)

        return {
            "entities": entities,
            "relations": relations,
            "graph_nodes": graph.number_of_nodes(),
            "graph_edges": graph.number_of_edges(),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_entities(self, text: str) -> dict[str, list[str]]:
        entities: dict[str, list[str]] = {
            "malware": [],
            "actor": [],
            "tool": [],
            "vulnerability": [],
            "tactic": [],
            "indicator": [],
        }

        # --- Regex pass ---
        for pattern_name, pattern in _INDICATOR_PATTERNS.items():
            matches = list({m.group() for m in pattern.finditer(text)})
            if pattern_name == "cve":
                entities["vulnerability"].extend(matches)
            else:
                entities["indicator"].extend(matches)

        # --- Transformer NER pass ---
        if self._ner:
            try:
                ner_results = self._ner(text[:512])  # model max length guard
                for item in ner_results:
                    label = item.get("entity_group", "")
                    word = item.get("word", "").strip()
                    if not word:
                        continue
                    mapped = _map_label(label)
                    if mapped and word not in entities[mapped]:
                        entities[mapped].append(word)
            except Exception as exc:  # noqa: BLE001
                log.warning("NER inference failed: %s", exc)

        # De-duplicate
        return {k: list(dict.fromkeys(v)) for k, v in entities.items()}

    def _extract_relations(
        self, entities: dict[str, list[str]], text: str
    ) -> list[dict[str, str]]:
        """
        Heuristic co-occurrence relations: if two named entities appear in the
        same sentence, emit a relation edge.  A real TiKG deployment would use
        a trained relation-extraction model here.
        """
        relations: list[dict[str, str]] = []
        sentences = re.split(r"(?<=[.!?])\s+", text)

        flat: list[tuple[str, str]] = []
        for etype, names in entities.items():
            for name in names:
                flat.append((name, etype))

        for sentence in sentences:
            present = [(n, t) for n, t in flat if n.lower() in sentence.lower()]
            for i, (n1, t1) in enumerate(present):
                for n2, t2 in present[i + 1 :]:
                    rel = _infer_relation(t1, t2)
                    relations.append({"head": n1, "relation": rel, "tail": n2})

        return relations

    def _build_graph(
        self,
        entities: dict[str, list[str]],
        relations: list[dict[str, str]],
    ) -> nx.DiGraph:
        G = nx.DiGraph()
        for etype, names in entities.items():
            for name in names:
                G.add_node(name, type=etype)
        for rel in relations:
            G.add_edge(rel["head"], rel["tail"], relation=rel["relation"])
        return G


# ------------------------------------------------------------------
# Label mapping helpers
# ------------------------------------------------------------------

_LABEL_MAP = {
    # SecRoBERTa / CyNER labels
    "MAL": "malware",
    "MALWARE": "malware",
    "ACT": "actor",
    "ACTOR": "actor",
    "THREAT-ACTOR": "actor",
    "TOOL": "tool",
    "SOFT": "tool",
    "SOFTWARE": "tool",
    "VUL": "vulnerability",
    "VULN": "vulnerability",
    "VULNERABILITY": "vulnerability",
    "TAC": "tactic",
    "TACTIC": "tactic",
    "TECHNIQUE": "tactic",
    # Generic NER fallbacks
    "ORG": "actor",
    "PER": "actor",
    "MISC": "tool",
}


def _map_label(label: str) -> str | None:
    return _LABEL_MAP.get(label.upper())


def _infer_relation(type1: str, type2: str) -> str:
    rules = {
        ("actor", "malware"): "uses",
        ("malware", "tool"): "leverages",
        ("actor", "tool"): "deploys",
        ("malware", "vulnerability"): "exploits",
        ("actor", "vulnerability"): "exploits",
        ("actor", "tactic"): "employs",
        ("malware", "indicator"): "associated_with",
        ("actor", "indicator"): "associated_with",
    }
    return rules.get((type1, type2)) or rules.get((type2, type1)) or "related_to"
