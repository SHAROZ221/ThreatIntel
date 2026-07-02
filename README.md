# 🔍 ThreatIntel Aggregator

### Multi-Source Threat Intelligence & IOC Management Platform

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)
![AbuseIPDB](https://img.shields.io/badge/API-AbuseIPDB-orange?style=flat-square)
![VirusTotal](https://img.shields.io/badge/API-VirusTotal-394EFF?style=flat-square)
![AlienVault OTX](https://img.shields.io/badge/API-AlienVault%20OTX-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-00ff88?style=flat-square)
![Type](https://img.shields.io/badge/Type-Threat%20Intel%20%2F%20OSINT-red?style=flat-square)

*A Python-based threat intelligence platform that aggregates IOCs, queries live reputation APIs, and provides a web dashboard for searching, adding, managing, and exporting threat indicators — built for SOC analyst workflows.*

---

## 🔍 What is ThreatIntel Aggregator?

In a Security Operations Center, analysts constantly look up **Indicators of Compromise (IOCs)** — malicious IPs, domains, and file hashes — across multiple sources to determine threat risk.

This tool centralises that process. It stores IOCs in a local database, lets you search and filter them instantly, enriches indicators with live **AbuseIPDB**, **VirusTotal**, and **AlienVault OTX** reputation data simultaneously, and presents everything through a clean web dashboard.

This mirrors real-world SOC tooling like MISP, OpenCTI, and ThreatConnect — but built from scratch in Python.

---

## ⚙️ How It Works

```
Analyst submits IOC (IP / Domain / Hash)
            │
            ▼
    Auto-Detects IOC Format (Regex patterns)
            │
            ▼
    Search threats.db ──► Found? ──► Display result + risk score
            │
            ▼
    Triple API Enrichment (based on IOC type)
       │                  │                      │
       ▼                  ▼                      ▼
AbuseIPDB Lookup    VirusTotal Lookup     AlienVault OTX Lookup
(IPs only)          (IP / Domain / Hash)  (IP / Domain / Hash)
  abuse score         malicious engines     pulse counts
  report count        suspicious count      pulse details
  country origin      total engines         pulses description
       │                  │                      │
       └──────────────────┼──────────────────────┘
                          ▼
            Display unified intelligence report
                          │
                          ▼
            Export ──► Download full IOC list as CSV
```

All IOCs are stored with a type, category, and risk score. The dashboard shows live statistics and lets authenticated analysts add, search, edit, delete, or export indicators.

---

## 🔒 Security & Access Control Features

We have upgraded ThreatIntel to include enterprise-grade security and access controls:

### 🔑 1. Analyst Access Portal (Authentication)
*   **Flask-Login**: The dashboard operates in a **guest/read-only** mode by default. Forms to add threats, edit entries, delete IOCs, or download CSV logs are hidden/disabled until an analyst logs in.
*   **Role-Based Security**: Credentials are encrypted and hashed inside the database using Werkzeug's secure hashing algorithm (`pbkdf2:sha256` or `scrypt`).
*   **Seeded Admin Account**: Comes pre-configured with a default analyst login (`admin` / `admin123`) created by running `init_db.py`.

### 📋 2. Real-Time Audit Log Trail (`audit.log`)
*   Every administrative transaction is recorded to a local audit log file for SOC accountability, documenting:
    *   User Logins & Logouts
    *   Threat additions, modifications, and deletions
    *   CSV export file downloads
*   *Example log line:*
    `[2026-07-02 07:45:12 UTC] User: admin | Action: ADD_THREAT | Indicator: 185.220.101.1`

### 🛡️ 3. Safe Database Connection Lifecycle
*   Avoids connection lockups and descriptor leaks by binding database connections directly to the Flask request pipeline context (`flask.g` and `@app.teardown_appcontext`).

### 🧼 4. Input Sanitization (XSS Mitigation)
*   Replaced custom regex tag-stripping with safe HTML escaping (`html.escape`), neutralizing malicious scripts entered in IOC category or indicator forms.

---

## 🔌 Threat Intel Enrichment APIs

| Source | Indicator Types | What is Fetched |
|--------|-----------------|-----------------|
| **AbuseIPDB** | IP Address | Abuse score %, total report count, country of origin, last reported date |
| **VirusTotal** | IP, Domain, Hash | Malicious/suspicious counts, total antivirus engine ratings |
| **AlienVault OTX** | IP, Domain, Hash | Total threat pulse counts, names, descriptions, and creation dates |

*Note: OTX lookups run out-of-the-box and do not require an API key.*

---

## 🧩 IOC Format Auto-Detection (Regex Patterns)

When an analyst searches under the "All" type, ThreatIntel automatically parses the indicator format to run the correct query dispatches:
*   **IP Address**: Matches IPv4 or standard IPv6 formats.
*   **File Hash**: Identifies MD5 (32 hex characters), SHA-1 (40 characters), or SHA-256 (64 characters) hash structures.
*   **Domain**: Standard URL domain parsing (e.g. `domain.com`).

---

## 🚀 Getting Started

**1. Clone the repository**

```bash
git clone https://github.com/SHAROZ221/ThreatIntel.git
cd ThreatIntel
```

**2. Install dependencies**

```bash
pip install -r Requirements.txt
pip install flask-login pytest
```

**3. Set up your API keys**

Create a `.env` file in the root directory:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
FLASK_SECRET_KEY=your_random_flask_secret_key
```

Get free API keys at:
- [abuseipdb.com](https://www.abuseipdb.com/register)
- [virustotal.com](https://www.virustotal.com)

**4. Initialise the database & seed admin**

This creates the tables and seeds your default analyst account (`admin` / `admin123`):

```bash
python init_db.py
```

**5. (Optional) Seed sample threat data**

```bash
python seed_data.py
```

**6. Run the app**

```bash
python app.py
```

**7. Run the test suite**

Ensure all authentication, session routing, and CSV export tests pass successfully:

```bash
python -m pytest test.py
```

**8. Open the dashboard**

```
http://localhost:5000/
```

---

## 📊 Dashboard Features

The web dashboard provides:

- **Live statistics** — total IOC count, breakdown by IP / Domain / Hash
- **Triple-source IOC enrichment** — AbuseIPDB + VirusTotal + AlienVault OTX results displayed side by side
- **Smart IOC search** — auto-detects formats and queries the right API
- **Analyst authentication** — login and register portals
- **Add new threats** — submit indicator, type, category, and risk score (requires login)
- **Edit/Delete indicators** — modify or remove registry entries (requires login)
- **Recent threats table** — full IOC list ordered by most recently added
- **IOC type chart** — donut chart showing live breakdown of IP / Domain / Hash counts
- **Export to CSV** — download the full IOC list as a `.csv` file with one click (requires login)

---

## 📁 Project Structure

```
ThreatIntel/
├── app.py           → Flask web server, routes, database contexts, and API clients
├── init_db.py       → Creates database tables & seeds admin user (admin/admin123)
├── seed_data.py     → Populates DB with sample IOCs for testing
├── view_data.py     → CLI utility to inspect database contents
├── test.py          → Test suite covering login flows and authenticated exports
├── templates/
│   ├── index.html   → Main web dashboard UI (OTX pulses, charts, forms)
│   ├── login.html   → Sleek analyst login interface
│   ├── register.html → SOC analyst registration portal
│   └── edit.html    → Edit IOC form
├── threats.db       → SQLite IOC database (auto-generated)
├── audit.log        → Logs all analyst modifications and logins (auto-generated)
└── .env             → API keys (not committed — see .gitignore)
```

---

## 🗄️ Database Schemas

### threats table:
```sql
CREATE TABLE threats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator   TEXT NOT NULL,      -- The IOC value (IP, domain, hash)
    type        TEXT NOT NULL,      -- 'IP', 'Domain', or 'Hash'
    category    TEXT NOT NULL,      -- e.g. 'Malware', 'Phishing', 'C2'
    risk_score  INTEGER NOT NULL    -- 0–100 severity rating
);
```

### users table:
```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,      -- Encrypted credential hash
    role          TEXT DEFAULT 'analyst' -- 'admin' or 'analyst'
);
```

---

## 🧰 Built With

- **Flask** — Web framework and routing
- **Flask-Login** — Access control and session manager
- **SQLite3** — Thread-safe local database
- **AbuseIPDB API** — Live IP reputation, abuse score, reports, and country
- **VirusTotal API** — Multi-engine malware detection for IPs, domains, and file hashes
- **AlienVault OTX API** — Pulsed community threat indicators (IP, domain, hashes)
- **python-dotenv** — Secure API key management via `.env`
- **Chart.js** — Live donut chart on the dashboard
- **HTML / CSS / JS** — Dashboard frontend with CSV export

---