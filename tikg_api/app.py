"""
TiKG API - Threat Intelligence Knowledge Graph Service
Wraps the TiKG NLP pipeline as a REST API for integration with Netdata.
"""

import os
import time
import logging
from collections import defaultdict
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from extractor import ThreatExtractor

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger(__name__)

app = Flask(__name__)

extractor = ThreatExtractor(model_name=os.getenv("MODEL_NAME", "secureBERT"))

# In-memory metrics store (rolling window of last 1000 analyses)
_stats = {
    "total_analyses": 0,
    "total_entities": defaultdict(int),
    "recent_threats": [],
    "last_updated": None,
}


@app.get("/health")
def health():
    return jsonify({"status": "ok", "model": extractor.model_name})


@app.post("/analyze")
def analyze():
    """
    Analyze a threat report and return extracted entities + knowledge graph edges.

    Request body:
        { "text": "<report text>", "source": "<optional label>" }

    Response:
        {
          "entities": { "malware": [...], "actor": [...], "tool": [...], "vulnerability": [...] },
          "relations": [{ "head": "...", "relation": "...", "tail": "..." }],
          "graph_nodes": int,
          "graph_edges": int,
          "processing_ms": int
        }
    """
    data = request.get_json(force=True)
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "Field 'text' is required"}), 400

    t0 = time.monotonic()
    result = extractor.extract(text)
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    # Update stats
    _stats["total_analyses"] += 1
    for etype, entities in result["entities"].items():
        _stats["total_entities"][etype] += len(entities)
    _stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    threat_entry = {
        "source": data.get("source", "unknown"),
        "timestamp": _stats["last_updated"],
        "entity_counts": {k: len(v) for k, v in result["entities"].items()},
    }
    _stats["recent_threats"] = (_stats["recent_threats"] + [threat_entry])[-1000:]

    result["processing_ms"] = elapsed_ms
    return jsonify(result)


@app.get("/metrics")
def metrics():
    """
    Netdata-compatible metrics endpoint.
    Returns cumulative and recent entity counts for the custom collector.
    """
    recent = _stats["recent_threats"][-100:]  # last 100 reports

    # Counts across recent window
    window_counts: dict[str, int] = defaultdict(int)
    for entry in recent:
        for etype, count in entry["entity_counts"].items():
            window_counts[etype] += count

    return jsonify({
        "total_analyses": _stats["total_analyses"],
        "cumulative_entities": dict(_stats["total_entities"]),
        "window_entities": dict(window_counts),
        "window_size": len(recent),
        "last_updated": _stats["last_updated"],
    })


@app.get("/graph/recent")
def graph_recent():
    """Return the last N threat entries for dashboard display."""
    n = int(request.args.get("n", 10))
    return jsonify(_stats["recent_threats"][-n:])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
