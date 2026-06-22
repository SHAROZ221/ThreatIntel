# 🔍 ThreatIntel Aggregator

### Multi-Source Threat Intelligence & IOC Management Platform

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)
![AbuseIPDB](https://img.shields.io/badge/API-AbuseIPDB-orange?style=flat-square)
![VirusTotal](https://img.shields.io/badge/API-VirusTotal-394EFF?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-00ff88?style=flat-square)
![Type](https://img.shields.io/badge/Type-Threat%20Intel%20%2F%20OSINT-red?style=flat-square)

*A Python-based threat intelligence platform that aggregates IOCs, queries live reputation APIs, and provides a web dashboard for searching, adding, managing, and exporting threat indicators — built for SOC analyst workflows.*

---

## 🔍 What is ThreatIntel Aggregator?

In a Security Operations Center, analysts constantly look up **Indicators of Compromise (IOCs)** — malicious IPs, domains, and file hashes — across multiple sources to determine threat risk.

This tool centralises that process. It stores IOCs in a local database, lets you search and filter them instantly, enriches indicators with live **AbuseIPDB** and **VirusTotal** reputation data simultaneously, and presents everything through a clean web dashboard.

This mirrors real-world SOC tooling like MISP, OpenCTI, and ThreatConnect — but built from scratch in Python.

---

## ⚙️ How It Works

```
Analyst submits IOC (IP / Domain / Hash)
            │
            ▼
    Search threats.db ──► Found? ──► Display result + risk score
            │
            ▼
    Dual API Enrichment (based on IOC type)
       │                        │
       ▼                        ▼
AbuseIPDB Lookup          VirusTotal Lookup
(IPs only)                (IP / Domain / Hash)
  abuse score               malicious engines
  report count              suspicious count
  country origin            total engine count
       │                        │
       └───────────┬────────────┘
                   ▼
    Display unified intelligence report
                   │
                   ▼
    Export ──► Download full IOC list as CSV
```

All IOCs are stored with a type, category, and risk score. The dashboard shows live statistics and lets analysts add, search, delete, or export indicators.

---

## 🧩 IOC Types Supported

| Type | Example | AbuseIPDB | VirusTotal |
|------|---------|-----------|------------|
| IP Address | `185.220.101.1` | ✅ | ✅ |
| Domain | `evil-domain.xyz` | ❌ | ✅ |
| File Hash | `d41d8cd98f00b204...` | ❌ | ✅ |

---

## 🚀 Getting Started

**1. Clone the repository**

```bash
git clone https://github.com/SHAROZ221/ThreatIntel.git
cd ThreatIntel
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Set up your API keys**

Create a `.env` file in the root directory:

```
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

Get free API keys at:
- [abuseipdb.com](https://www.abuseipdb.com/register)
- [virustotal.com](https://www.virustotal.com)

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
- **Dual-source IOC enrichment** — AbuseIPDB + VirusTotal results displayed side by side
- **IOC search** — look up any indicator with optional type filter
- **Add new threats** — submit indicator, type, category, and risk score
- **Delete indicators** — remove resolved or false-positive entries
- **Recent threats table** — full IOC list ordered by most recently added
- **IOC type chart** — donut chart showing live breakdown of IP / Domain / Hash counts
- **Export to CSV** — download the full IOC list as a `.csv` file with one click

---

## 📤 Export Feature

The dashboard includes a **Export CSV** button available in two places — the top navigation bar and next to the threats table header.

Clicking it instantly downloads a file named `threatintel-iocs-YYYY-MM-DD.csv` containing all current indicators in the following format:

```
id,indicator,type,category,risk_score
1,"185.220.101.1",IP,Malware,95
2,"evil-phish-domain.xyz",Domain,Phishing,78
3,"d41d8cd98f00b204e9800998ecf8427e",Hash,Malware,85
```

This is useful for:
- Sharing IOC lists with other analysts or teams
- Importing into SIEM tools like Splunk or Microsoft Sentinel
- Keeping an offline backup of your threat database
- Reporting and documentation during incident response

---

## 📁 Project Structure

```
ThreatIntel/
├── app.py           → Flask web server, all routes, AbuseIPDB + VirusTotal logic
├── init_db.py       → Creates the SQLite threats database & schema
├── seed_data.py     → Populates DB with sample IOCs for testing
├── view_data.py     → CLI utility to inspect database contents
├── test.py          → Test suite for core functionality
├── templates/
│   ├── index.html   → Main web dashboard UI (charts, search, enrichment)
│   └── edit.html    → Edit IOC form
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
- **AbuseIPDB API** — Live IP reputation, abuse score, report count, and country
- **VirusTotal API** — Multi-engine malware detection for IPs, domains, and file hashes
- **python-dotenv** — Secure API key management via `.env`
- **Chart.js** — Live donut chart on the dashboard
- **HTML / CSS / JS** — Dashboard frontend with CSV export

---