#!/usr/bin/env python3
"""
Netdata custom collector - Threat Intelligence Knowledge Graph metrics.
Polls the TiKG API and exposes entity counts as Netdata charts.

Place this file in /etc/netdata/custom-plugins.d/ (mapped via docker-compose volume).
Netdata will auto-discover and run it every collection interval (default: 1s).
"""

import os
import json
import urllib.request
import urllib.error

from bases.FrameworkServices.SimpleService import SimpleService

# Netdata plugin metadata
priority = 90000
retries = 5
update_every = 30  # poll every 30 seconds (TiKG analysis is expensive)

TIKG_URL = os.getenv("TIKG_API_URL", "http://localhost:5000") + "/metrics"

ORDER = [
    "cumulative_entities",
    "window_entities",
    "analyses",
]

CHARTS = {
    "cumulative_entities": {
        "options": [None, "Cumulative Threat Entities Detected", "entities", "threat_intel", "tikg.cumulative", "stacked"],
        "lines": [
            ["cum_malware",       "malware",       "absolute"],
            ["cum_actor",         "actor",         "absolute"],
            ["cum_tool",          "tool",          "absolute"],
            ["cum_vulnerability", "vulnerability", "absolute"],
            ["cum_tactic",        "tactic",        "absolute"],
            ["cum_indicator",     "indicator",     "absolute"],
        ],
    },
    "window_entities": {
        "options": [None, "Recent Threat Entities (last 100 reports)", "entities", "threat_intel", "tikg.window", "stacked"],
        "lines": [
            ["win_malware",       "malware",       "absolute"],
            ["win_actor",         "actor",         "absolute"],
            ["win_tool",          "tool",          "absolute"],
            ["win_vulnerability", "vulnerability", "absolute"],
            ["win_tactic",        "tactic",        "absolute"],
            ["win_indicator",     "indicator",     "absolute"],
        ],
    },
    "analyses": {
        "options": [None, "Total Threat Reports Analyzed", "reports", "threat_intel", "tikg.analyses", "area"],
        "lines": [
            ["total_analyses", "analyzed", "absolute"],
        ],
    },
}


class Service(SimpleService):
    def __init__(self, configuration=None, name=None):
        SimpleService.__init__(self, configuration=configuration, name=name)
        self.order = ORDER
        self.definitions = CHARTS
        self._last_data = {}

    def check(self):
        try:
            self._fetch()
            return True
        except Exception as exc:
            self.error(f"TiKG API not reachable at {TIKG_URL}: {exc}")
            return False

    def get_data(self):
        try:
            return self._fetch()
        except Exception as exc:
            self.error(f"Failed to fetch TiKG metrics: {exc}")
            return None

    def _fetch(self):
        req = urllib.request.Request(TIKG_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read())

        cum = payload.get("cumulative_entities", {})
        win = payload.get("window_entities", {})

        return {
            "cum_malware":        cum.get("malware", 0),
            "cum_actor":          cum.get("actor", 0),
            "cum_tool":           cum.get("tool", 0),
            "cum_vulnerability":  cum.get("vulnerability", 0),
            "cum_tactic":         cum.get("tactic", 0),
            "cum_indicator":      cum.get("indicator", 0),
            "win_malware":        win.get("malware", 0),
            "win_actor":          win.get("actor", 0),
            "win_tool":           win.get("tool", 0),
            "win_vulnerability":  win.get("vulnerability", 0),
            "win_tactic":         win.get("tactic", 0),
            "win_indicator":      win.get("indicator", 0),
            "total_analyses":     payload.get("total_analyses", 0),
        }
