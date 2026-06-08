# 🔍 ThreatIntel Aggregator

### Multi-Source Threat Intelligence & IOC Management Platform

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)
![AbuseIPDB](https://img.shields.io/badge/API-AbuseIPDB-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-00ff88?style=flat-square)
![Type](https://img.shields.io/badge/Type-Threat%20Intel%20%2F%20OSINT-red?style=flat-square)

*A Python-based threat intelligence platform that aggregates IOCs, queries live reputation APIs, and provides a web dashboard for searching, adding, and managing threat indicators — built for SOC analyst workflows.*

---

## 🔍 What is ThreatIntel Aggregator?

In a Security Operations Center, analysts constantly look up **Indicators of Compromise (IOCs)** — malicious IPs, domains, and file hashes — across multiple sources to determine threat risk.

This tool centralises that process. It stores IOCs in a local database, lets you search and filter them instantly, enriches IPs with live **AbuseIPDB** reputation data, and presents everything through a clean web dashboard.

This mirrors real-world SOC tooling like MISP, OpenCTI, and ThreatConnect — but built from scratch in Python.

---

## ⚙️ How It Works

```
Analyst submits IOC (IP / Domain / Hash)
            │
            ▼
    Search threats.db ──► Found? ──► Display result + risk score
            │
         Not found?
            │
            ▼
    AbuseIPDB API Lookup (for IPs)
            │
            ▼
    Store result ──► Display enriched intelligence
```

All IOCs are stored with a type, category, and risk score. The dashboard shows live statistics and lets analysts add, search, or delete indicators.

---

## 🧩 IOC Types Supported

| Type | Example | Use Case |
|------|---------|----------|
| IP Address | `192.168.1.1` | Malicious host, C2 server |
| Domain | `evil-domain.xyz` | Phishing, malware delivery |
| File Hash | `d41d8cd98f00b204...` | Malware sample identification |

---

## 🚀 Getting Started

**1. Clone the repository**

```bash
git clone https://github.com/SHAROZ221/threat-intelligence-aggregator.git
cd threat-intelligence-aggregator
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Set up your AbuseIPDB API key**

Create a `.env` file in the root directory:

```
ABUSEIPDB_API_KEY=your_api_key_here
```

Get a free API key at [abuseipdb.com](https://www.abuseipdb.com/register)

**4. Initialise the database**

```bash
python init_db.py
```

**5. (Optional) Seed with sample data**

```bash
python seed_data.py
```

**6. Run the app**

```bash
python app.py
```

**7. Open the dashboard**

```
http://localhost:5000/
```

---

## 📊 Dashboard Features

The web dashboard provides:

- **Live statistics** — total IOC count, breakdown by IP / Domain / Hash
- **IOC search** — look up any indicator with optional type filter
- **Add new threats** — submit indicator, type, category, and risk score
- **Delete indicators** — remove resolved or false-positive entries
- **Recent threats table** — full IOC list ordered by most recently added

---

## 📁 Project Structure

```
threat-intelligence-aggregator/
├── app.py           → Flask web server, all routes & dashboard logic
├── init_db.py       → Creates the SQLite threats database & schema
├── seed_data.py     → Populates DB with sample IOCs for testing
├── view_data.py     → CLI utility to inspect database contents
├── test.py          → Test suite for core functionality
├── templates/
│   └── index.html   → Web dashboard UI
├── threats.db       → SQLite IOC database (auto-generated)
└── .env             → API keys (not committed — see .gitignore)
```

---

## 🗄️ Database Schema

```sql
CREATE TABLE threats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator   TEXT NOT NULL,      -- The IOC value (IP, domain, hash)
    type        TEXT NOT NULL,      -- 'IP', 'Domain', or 'Hash'
    category    TEXT NOT NULL,      -- e.g. 'Malware', 'Phishing', 'C2'
    risk_score  INTEGER NOT NULL    -- 0–100 severity rating
)
```

---

## 🧰 Built With

- **Flask** — Web framework and routing
- **SQLite3** — Lightweight IOC storage (no external DB required)
- **AbuseIPDB API** — Live IP reputation and abuse score lookups
- **python-dotenv** — Secure API key management via `.env`
- **HTML / CSS** — Dashboard frontend

---

## 🔐 Security Note

Never commit your `.env` file or expose your API keys. The `.gitignore` is configured to exclude `.env` by default. If you accidentally expose a key, regenerate it immediately at [abuseipdb.com](https://www.abuseipdb.com).

---

**Sharoz** · BCA Year 3 · Cybersecurity (SOC Track)

[github.com/SHAROZ221](https://github.com/SHAROZ221)
