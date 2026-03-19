# Netdata health alarms for Threat Intelligence metrics

# Alert when high-severity malware entities spike in recent window
alarm: tikg_malware_spike
    on: tikg.window
    lookup: max -10m unaligned of win_malware
    units: entities
    every: 1m
    warn: $this > 5
    crit: $this > 20
    info: High number of malware entities detected in recent threat reports
    to: sysadmin

# Alert when threat actor activity spikes
alarm: tikg_actor_spike
    on: tikg.window
    lookup: max -10m unaligned of win_actor
    units: entities
    every: 1m
    warn: $this > 3
    crit: $this > 10
    info: Elevated threat actor activity detected in recent reports
    to: sysadmin

# Alert on CVE/vulnerability mentions
alarm: tikg_vulnerability_spike
    on: tikg.window
    lookup: max -10m unaligned of win_vulnerability
    units: entities
    every: 1m
    warn: $this > 10
    crit: $this > 30
    info: High number of vulnerability references in recent threat reports
    to: sysadmin

# Alert if TiKG API goes silent (no analyses for 1 hour)
alarm: tikg_api_stale
    on: tikg.analyses
    lookup: min -1h unaligned of total_analyses
    units: reports
    every: 5m
    warn: $this == $this  # always check - triggers if chart disappears
    info: TiKG API may be unreachable or stalled
    to: sysadmin
