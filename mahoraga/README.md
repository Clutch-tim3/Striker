# Mahoraga — Adaptive Cybersecurity EDR

**By Donington Vale · Available on [clive.dev](https://clive.dev)**

Mahoraga is an adaptive endpoint detection and response (EDR) desktop application.
It detects, understands, and neutralises cyber threats in real time, then archives
every threat as a structured "antibody" so future encounters with the same or similar
attacks are resolved faster — like the human immune system.

---

## Architecture

```
LAYER 0  UI Shell          Electron + Vanilla HTML/CSS/JS
LAYER 1  Sensor Engine     Python — psutil, Watchdog, Scapy
LAYER 2  Detection Engine  Python ML — Isolation Forest, Random Forest
LAYER 3  Analysis Engine   MITRE ATT&CK mapping, severity scoring
LAYER 4  Response Engine   Process kill, quarantine, network isolation
LAYER 5  Antibody Archive  SQLite + FAISS — encrypted local storage
LAYER 6  Adaptation Loop   Nightly model retraining on local threats
[v3]     Federated Layer   AWS Lambda + S3 — global threat sharing
```

---

## Quick Start (Development)

```bash
# Install and run
bash scripts/dev.sh
```

Requires: Node.js 18+, Python 3.11+

---

## Build for Distribution

```bash
# Full build — Python binary + Electron installer
bash scripts/build-all.sh
```

Outputs:
- `dist/mahoraga-mac.dmg`
- `dist/mahoraga-win.exe`
- `dist/mahoraga-linux.AppImage`

---

## Python Dependencies

```bash
pip install -r python/requirements.txt
```

| Package       | Purpose                          |
|---------------|----------------------------------|
| psutil        | Process + network monitoring     |
| watchdog      | File system events               |
| scikit-learn  | Isolation Forest, Random Forest  |
| numpy         | Feature vectors                  |
| faiss-cpu     | Similarity search (antibodies)   |
| cryptography  | AES-256 archive encryption       |

---

## Tier System

| Feature                  | Free | Pro |
|--------------------------|------|-----|
| Real-time detection      | ✓    | ✓   |
| Antibody archive         | ✓    | ✓   |
| Nightly adaptation       | ✓    | ✓   |
| Federated global model   | ✗    | ✓   |
| Global threat map        | ✗    | ✓   |

Get a Pro license at **clive.dev**

---

## Data & Privacy

- All data stays on-device in v1/v2
- Federated upload (v3 Pro) sends **only anonymous behaviour vectors** — never file paths, usernames, IPs, or raw telemetry
- Archive stored at `~/.mahoraga/archive.db` (AES-256 encrypted)
