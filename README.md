# Security Monitor

Combines **Netdata** real-time infrastructure monitoring with a **TiKG** (Threat Intelligence Knowledge Graph) NLP service. Threat reports are analyzed to extract entities (malware, actors, tools, CVEs) and relationships, which are surfaced as live metrics and alerts in the Netdata dashboard.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Ubuntu Server                                   │
│                                                  │
│  ┌─────────────────┐    ┌─────────────────────┐  │
│  │   Netdata       │    │   TiKG API          │  │
│  │  :19999         │◄───│   :5000             │  │
│  │                 │    │                     │  │
│  │  custom plugin  │    │  /analyze  (POST)   │  │
│  │  threat_intel   │    │  /metrics  (GET)    │  │
│  │  .chart.py      │    │  /health   (GET)    │  │
│  └─────────────────┘    └─────────────────────┘  │
└──────────────────────────────────────────────────┘
```

## Quick Start (Ubuntu 22.04 / 24.04)

```bash
git clone <this-repo> /opt/security-monitor
cd /opt/security-monitor
sudo bash scripts/install.sh
```

The installer will:
1. Install Docker + Docker Compose plugin
2. Open UFW firewall ports 19999 and 5000
3. Build the TiKG API container (downloads transformer models ~1-2 GB)
4. Pull and start Netdata
5. Print access URLs

## Manual Start

```bash
cp .env.example .env
# edit .env if needed
docker compose up -d
```

## Submitting Threat Reports

```bash
# From a file
bash scripts/analyze.sh /path/to/report.txt --source "CISA Advisory"

# Piped text
echo "APT28 used Mimikatz and Industroyer targeting ICS systems (CVE-2022-30190)" \
  | bash scripts/analyze.sh --source "manual"

# Direct curl
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Lazarus Group deployed custom RAT...", "source": "threat-feed"}'
```

## Netdata Dashboard

Open `http://<server-ip>:19999` — look for the **threat_intel** section with three charts:
- **Cumulative entities** — all-time totals by entity type
- **Recent entities** — last 100 analyzed reports
- **Analyses** — total report count

## Alerts

Health alarms fire when:
| Condition | Warning | Critical |
|-----------|---------|----------|
| Malware entities (10 min window) | > 5 | > 20 |
| Threat actor entities | > 3 | > 10 |
| Vulnerability mentions | > 10 | > 30 |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TIKG_MODEL` | `secureBERT` | NER model (`secureBERT` or `bert-base-NER`) |
| `LOG_LEVEL` | `INFO` | TiKG API log level |
| `NETDATA_CLAIM_TOKEN` | _(empty)_ | Netdata Cloud token (optional) |

## Entity Types

| Type | Examples |
|------|---------|
| `malware` | WannaCry, Cobalt Strike, Industroyer |
| `actor` | APT28, Lazarus Group, Sandworm |
| `tool` | Mimikatz, Metasploit, PsExec |
| `vulnerability` | CVE-2022-30190, CVE-2021-44228 |
| `tactic` | lateral movement, credential dumping |
| `indicator` | IPs, domains, MD5/SHA256 hashes, URLs |
