# 🔍 ThreatIntel Aggregator

### Multi-Source Threat Intelligence & IOC Management Platform

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)
![AbuseIPDB](https://img.shields.io/badge/API-AbuseIPDB-orange?style=flat-square)
![VirusTotal](https://img.shields.io/badge/API-VirusTotal-394EFF?style=flat-square)
![AlienVault OTX](https://img.shields.io/badge/API-AlienVault%20OTX-blue?style=flat-square)
![REST API](https://img.shields.io/badge/REST-API%20v1-brightgreen?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-00ff88?style=flat-square)
![Type](https://img.shields.io/badge/Type-Threat%20Intel%20%2F%20OSINT-red?style=flat-square)

*A Python-based threat intelligence platform that aggregates IOCs, queries live reputation APIs, provides a REST API, and delivers a full-featured web dashboard for SOC analyst workflows — including bulk import, admin controls, and audit logging.*

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
                 ┌────────┴────────┐
                 ▼                 ▼
         Export to CSV      REST API v1
         (authenticated)    (API key auth)
```

All IOCs are stored with a type, category, risk score, and creation timestamp. The dashboard shows live statistics, a 30-day activity timeline, and lets authenticated analysts add, search, bulk-import, edit, delete, or export indicators.

---

## 📊 Dashboard Features

| Feature | Description |
|---|---|
| **Live Statistics** | Total IOC count, breakdown by IP / Domain / Hash with ratios |
| **IOC Activity Timeline** | Chart.js line graph — indicators added per day over last 30 days |
| **IOC Type Donut Chart** | Live breakdown of IP / Domain / Hash distribution |
| **Triple-Source Enrichment** | AbuseIPDB + VirusTotal + AlienVault OTX results in one report |
| **Smart IOC Search** | Auto-detects IP / Domain / Hash format, queries the right API |
| **Bulk IOC Import** | Paste or upload `.txt`/`.csv` — auto-detects types, skips duplicates |
| **Add / Edit / Delete** | Full CRUD on indicators (requires login) |
| **Export to CSV** | Download full IOC list as `.csv` (requires login) |
| **Auto Feed Sync** | Background sync from Feodo Tracker & URLhaus every 6 hours |
| **Manual Feed Sync** | Trigger OSINT feed sync manually from the sidebar |
| **Analyst Authentication** | Login / register portals with session management |
| **Admin Control Panel** | User management, API key lifecycle, audit log viewer |

---

## 🔒 Security & Access Control

### 🔑 1. Role-Based Access Control (RBAC)
- **Guest / Read-Only** mode by default — add/edit/delete forms are hidden until login
- Two roles: `admin` and `analyst`
- Admins get access to `/admin` panel, API key management, and user controls
- `admin_required` decorator enforces role checks on all admin routes

### 📋 2. Real-Time Audit Log Trail (`audit.log`)
Every administrative action is recorded for SOC accountability:
- User logins & logouts
- Threat additions, edits, and deletions
- Bulk imports with counts
- CSV exports
- API key generation & revocation
- Admin user promote / demote / delete actions

```
[2026-08-01 19:26:26 UTC] User: admin | Action: USER_LOGIN
[2026-08-01 19:26:41 UTC] User: admin | Action: BULK_IMPORT | Added 12 (IP:8 Domain:4 Hash:0) Skipped:2
[2026-08-01 19:28:00 UTC] User: admin | Action: GENERATE_API_KEY | name: SIEM Integration
```

### 🛡️ 3. Input Sanitization (XSS Mitigation)
- HTML escaping via `html.escape()` on all user-submitted indicator values and categories

### 🔒 4. Safe Database Connection Lifecycle
- Thread-safe connections bound to Flask request context (`flask.g` + `@app.teardown_appcontext`)

### ⏱️ 5. Rate Limiting
- Global: `100 requests / hour` per IP
- Login & Register: `5 requests / minute` (brute-force protection)
- Dashboard: `30 requests / minute`

---

## 🔌 Threat Intel Enrichment APIs

| Source | Indicator Types | What is Fetched |
|--------|-----------------|-----------------|
| **AbuseIPDB** | IP Address | Abuse score %, total report count, country of origin, last reported date |
| **VirusTotal** | IP, Domain, Hash | Malicious/suspicious counts, total antivirus engine ratings |
| **AlienVault OTX** | IP, Domain, Hash | Total threat pulse counts, names, descriptions, and creation dates |

> OTX lookups run out-of-the-box and do not require an API key.

All three API calls are dispatched **in parallel** using `ThreadPoolExecutor` for fast enrichment.

---

## 🌐 REST API v1

The platform exposes a programmatic REST API for integration with SIEMs, scripts, and other security tooling. All endpoints require an `X-API-Key` header (generated from the Admin Panel).

### Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/v1/iocs` | Any key | List all IOCs with optional filters |
| `GET` | `/api/v1/ioc/<indicator>` | Any key | Look up a single IOC by value |
| `POST` | `/api/v1/ioc` | Any key | Create a new IOC |
| `DELETE` | `/api/v1/ioc/<id>` | Admin key only | Delete an IOC by ID |

### Usage Examples

```bash
# List all IP indicators (page 1, 50 per page)
curl http://localhost:5000/api/v1/iocs?type=IP&page=1 \
  -H "X-API-Key: ti_your_key_here"

# Look up a specific indicator
curl http://localhost:5000/api/v1/ioc/185.220.101.1 \
  -H "X-API-Key: ti_your_key_here"

# Add a new IOC via JSON
curl -X POST http://localhost:5000/api/v1/ioc \
  -H "X-API-Key: ti_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "evil.com", "type": "Domain", "category": "Phishing", "risk_score": 80}'

# Delete an IOC (admin key required)
curl -X DELETE http://localhost:5000/api/v1/ioc/42 \
  -H "X-API-Key: ti_admin_key_here"
```

### Sample Response

```json
GET /api/v1/ioc/185.220.101.1

{
  "status": 200,
  "found": true,
  "ioc": {
    "id": 14,
    "indicator": "185.220.101.1",
    "type": "IP",
    "category": "Feodo Botnet IP",
    "risk_score": 85,
    "created_at": "2026-08-01 14:32:00"
  }
}
```

---

## 📋 Bulk IOC Import

Analysts can import hundreds of IOCs at once instead of adding them one by one:

- Click **"Import IOCs"** in the sidebar (requires login)
- **Paste** raw IOCs — one per line, or CSV format
- **Upload** a `.txt` or `.csv` file
- Auto-detects IP / Domain / Hash type per line
- Skips duplicates and counts unrecognised entries
- Returns a detailed import summary:

```
Import complete! Added 47 indicators (32 IPs, 12 Domains, 3 Hashes). Skipped 5 duplicates, 0 unrecognised.
```

**Supported formats:**
```
# Plain list (type auto-detected)
185.220.101.1
evil-phishing.com
a3f4b2c1d5e6...

# CSV (indicator, type, category, risk_score)
10.0.0.1,IP,Botnet C2,85
phish.xyz,Domain,Phishing,70
```

---

## 🧩 IOC Format Auto-Detection

ThreatIntel automatically parses the indicator format using regex:

| Format | Detection Rule |
|--------|---------------|
| **IP Address** | IPv4 `(\d{1,3}\.){3}\d{1,3}` or IPv6 (contains `:`) |
| **File Hash** | MD5 (32 hex), SHA-1 (40 hex), SHA-256 (64 hex) |
| **Domain** | `[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` |

---

## 🚀 Getting Started

**1. Clone the repository**

```bash
git clone https://github.com/SHAROZ221/ThreatIntel.git
cd ThreatIntel
```

**2. Create a virtual environment & install dependencies**

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux / macOS

pip install -r Requirements.txt
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

```bash
python init_db.py
```

Creates all tables and seeds the default admin account (`admin` / `admin123`).

**5. (Existing installs only) Run the migration**

If you have an existing `threats.db`, run the one-time migration to add new columns:

```bash
python migrate.py
```

**6. (Optional) Seed sample threat data**

```bash
python seed_data.py
```

**7. Run the app**

```bash
python app.py
```

**8. Run the test suite**

```bash
python -m pytest test.py
```

**9. Open the dashboard**

```
http://localhost:5000/
```

**Default admin login:** `admin` / `admin123`

---

## 🔑 Admin Panel

Access the admin control panel at `http://localhost:5000/admin` (admin role required).

| Section | What You Can Do |
|---------|-----------------|
| **User Management** | View all analysts, promote to admin, demote to analyst, delete accounts |
| **API Key Management** | Generate named API keys per user, revoke keys instantly |
| **REST API Reference** | All 4 endpoints documented inline with example usage |
| **Audit Log Viewer** | Last 100 audit entries displayed newest-first in the browser |

---

## 📁 Project Structure

```
ThreatIntel/
├── app.py            → Flask server: routes, API clients, admin, REST API v1
├── init_db.py        → Creates all tables & seeds admin account (admin/admin123)
├── migrate.py        → One-time DB migration for existing installs (adds created_at, api_keys)
├── seed_data.py      → Populates DB with sample IOCs for testing
├── view_data.py      → CLI utility to inspect database contents
├── test.py           → Test suite covering login flows and authenticated exports
├── templates/
│   ├── index.html    → Main dashboard (timeline chart, bulk import modal, enrichment)
│   ├── admin.html    → Admin control panel (users, API keys, audit log)
│   ├── login.html    → Analyst login portal
│   ├── register.html → Analyst registration portal
│   ├── edit.html     → Edit IOC form
│   └── 429.html      → Rate limit error page
├── static/css/
│   └── style.css     → Dark GitHub-style design system + modal/admin styles
├── threats.db        → SQLite IOC database (auto-generated)
├── audit.log         → Audit trail (auto-generated)
└── .env              → API keys (not committed — see .gitignore)
```

---

## 🗄️ Database Schema

### threats table
```sql
CREATE TABLE threats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator   TEXT NOT NULL,       -- The IOC value (IP, domain, hash)
    type        TEXT NOT NULL,       -- 'IP', 'Domain', or 'Hash'
    category    TEXT NOT NULL,       -- e.g. 'Malware', 'Phishing', 'C2'
    risk_score  INTEGER NOT NULL,    -- 0–100 severity rating
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### users table
```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT DEFAULT 'analyst',  -- 'admin' or 'analyst'
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### api_keys table
```sql
CREATE TABLE api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    key         TEXT UNIQUE NOT NULL,   -- Prefixed: ti_<uuid>
    name        TEXT NOT NULL,          -- Label e.g. 'SIEM Integration'
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## 🧰 Built With

| Tool | Purpose |
|------|---------|
| **Flask** | Web framework and routing |
| **Flask-Login** | Session management and access control |
| **Flask-Limiter** | Rate limiting (brute-force protection) |
| **APScheduler** | Background OSINT feed sync (every 6 hours) |
| **SQLite3** | Thread-safe local IOC database |
| **AbuseIPDB API** | Live IP reputation, abuse score, reports, country |
| **VirusTotal API** | Multi-engine malware detection (IP, domain, hash) |
| **AlienVault OTX API** | Community threat pulses (IP, domain, hash) |
| **python-dotenv** | Secure `.env` API key management |
| **Chart.js** | Donut chart + 30-day timeline chart |
| **ThreadPoolExecutor** | Parallel API enrichment calls |
| **Werkzeug** | Password hashing (`pbkdf2:sha256` / `scrypt`) |
| **UUID** | Cryptographically unique REST API key generation |

---