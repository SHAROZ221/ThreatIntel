from flask import Flask, render_template, request, redirect, Response, g, url_for, flash, abort, jsonify
import sqlite3
import requests
import csv
import io
import re
import os
import html
from datetime import date, datetime
from dotenv import load_dotenv
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import uuid
import json
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "threat_intel_secret_key_12345")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("429.html"), 429

API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
DATABASE = "threats.db"
AUDIT_LOG_FILE = "audit.log"



# ── DATABASE & USER CLASS ───────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID from the SQLite database."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if row:
        return User(id=row[0], username=row[1], role=row[2])
    return None


def get_db():
    """Get thread-safe database connection using Flask's request context."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Ensure database connection is closed when the request ends."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# ── HELPERS & CLIENTS ────────────────────────────────────────────────────────

def log_audit(action, indicator=None):
    """Log user action to audit.log file with timestamp."""
    username = current_user.username if current_user.is_authenticated else "anonymous"
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    log_line = f"[{timestamp}] User: {username} | Action: {action}"
    if indicator:
        log_line += f" | Indicator: {indicator}"
    log_line += "\n"
    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        print("Audit Log Error:", e)


def check_ip_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        if response.status_code == 200:
            return response.json()["data"]
        return None
    except Exception as e:
        print("AbuseIPDB Error:", e)
        return None


def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total": sum(stats.values())
            }
        return None
    except Exception as e:
        print("VirusTotal IP Error:", e)
        return None


def check_domain_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total": sum(stats.values())
            }
        return None
    except Exception as e:
        print("VirusTotal Domain Error:", e)
        return None


def check_hash_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total": sum(stats.values())
            }
        return None
    except Exception as e:
        print("VirusTotal Hash Error:", e)
        return None


def check_otx(indicator, indicator_type):
    """Query AlienVault OTX Open Threat Exchange general API for reputation pulses."""
    otx_type_map = {
        "IP": "IPv4",
        "Domain": "domain",
        "Hash": "file"
    }
    otx_type = otx_type_map.get(indicator_type)
    if not otx_type:
        return None

    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/general"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "pulses": [
                    {
                        "name": p.get("name"),
                        "description": p.get("description"),
                        "created": p.get("created")
                    }
                    for p in data.get("pulse_info", {}).get("pulses", [])[:5]
                ]
            }
        return None
    except Exception as e:
        print("OTX Lookup Error:", e)
        return None


def sync_threat_feeds():
    """Query open intelligence feeds and synchronize database records."""
    print("Background Threat Feed Sync started...")
    feodo_ips = []
    urlhaus_domains = []

    # 1. Fetch Feodo Tracker (IP Blocklist)
    try:
        r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", timeout=15)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ip = line.split(":")[0] if ":" in line else line
                if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
                    feodo_ips.append(ip)
    except Exception as e:
        print("Feodo Tracker feed download error:", e)

    # 2. Fetch URLhaus (Malicious Domains)
    try:
        r = requests.get("https://urlhaus.abuse.ch/downloads/text/", timeout=15)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parsed = urlparse(line)
                domain = parsed.netloc
                if ":" in domain:
                    domain = domain.split(":")[0]
                if domain and not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain):
                    urlhaus_domains.append(domain)
    except Exception as e:
        print("URLhaus feed download error:", e)

    # 3. Commit to SQLite database
    inserted = 0
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Insert up to 50 new IP addresses from Feodo Tracker
        for ip in feodo_ips[:50]:
            cursor.execute("SELECT id FROM threats WHERE indicator = ?", (ip,))
            if cursor.fetchone() is None:
                cursor.execute(
                    "INSERT INTO threats (indicator, type, category, risk_score) VALUES (?, ?, ?, ?)",
                    (ip, "IP", "Feodo Botnet IP", 85)
                )
                inserted += 1

        # Insert up to 50 new domain names from URLhaus
        for domain in urlhaus_domains[:50]:
            cursor.execute("SELECT id FROM threats WHERE indicator = ?", (domain,))
            if cursor.fetchone() is None:
                cursor.execute(
                    "INSERT INTO threats (indicator, type, category, risk_score) VALUES (?, ?, ?, ?)",
                    (domain, "Domain", "URLhaus Malicious Domain", 75)
                )
                inserted += 1

        conn.commit()
        conn.close()
    except Exception as e:
        print("Database sync error:", e)
        return 0

    # 4. Log sync action to audit log
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    log_line = f"[{timestamp}] User: system | Action: AUTO_FEED_SYNC | Details: Imported {inserted} new indicators\n"
    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        print("Audit Log Sync Error:", e)

    print(f"Background Threat Feed Sync finished. Imported {inserted} indicators.")
    return inserted


def sanitize(value):
    """Secure sanitization using standard HTML escaping to prevent XSS."""
    return html.escape(value.strip())


def admin_required(f):
    """Decorator: restrict route to admin role only."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if current_user.role != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated_function


def generate_api_key():
    """Generate a unique API key prefixed with 'ti_'."""
    return f"ti_{uuid.uuid4().hex}"


def api_key_auth():
    """Authenticate request via X-API-Key header. Returns User or None."""
    key = request.headers.get("X-API-Key", "").strip()
    if not key:
        return None
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT u.id, u.username, u.role FROM api_keys ak "
        "JOIN users u ON ak.user_id = u.id WHERE ak.key = ?",
        (key,)
    )
    row = cursor.fetchone()
    return User(id=row[0], username=row[1], role=row[2]) if row else None


def auto_detect_type(indicator):
    """Automatically detect indicator type using regular expressions."""
    indicator_clean = indicator.strip()
    
    # IPv4 or IPv6 detection
    is_ip = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", indicator_clean) or ":" in indicator_clean
    if is_ip:
        return "IP"
        
    # MD5 (32), SHA-1 (40), SHA-256 (64) hex hash detection
    is_hash = re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", indicator_clean)
    if is_hash:
        return "Hash"
        
    # Domain detection
    is_domain = re.match(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", indicator_clean)
    if is_domain:
        return "Domain"
        
    return None


# ── ROUTES ───────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def home():
    result = None
    abuse_data = None
    vt_data = None
    otx_data = None

    db = get_db()
    cursor = db.cursor()

    if request.method == "POST":

        if "delete_id" in request.form:
            if not current_user.is_authenticated:
                flash("Authentication required to delete indicators.")
                return redirect(url_for("home"))
            
            delete_id = request.form["delete_id"]
            
            # Query indicator first for audit log
            cursor.execute("SELECT indicator FROM threats WHERE id = ?", (delete_id,))
            row = cursor.fetchone()
            deleted_indicator = row[0] if row else str(delete_id)

            cursor.execute("DELETE FROM threats WHERE id=?", (delete_id,))
            db.commit()
            log_audit("DELETE_THREAT", indicator=deleted_indicator)

        elif "new_indicator" in request.form:
            if not current_user.is_authenticated:
                flash("Authentication required to add indicators.")
                return redirect(url_for("home"))

            new_indicator = sanitize(request.form["new_indicator"])
            new_type = request.form["new_type"]
            new_category = sanitize(request.form["new_category"])

            try:
                new_risk = int(request.form["new_risk"])
                if not 0 <= new_risk <= 100:
                    new_risk = 0
            except ValueError:
                new_risk = 0

            if new_indicator:
                cursor.execute(
                    "INSERT INTO threats (indicator, type, category, risk_score) VALUES (?, ?, ?, ?)",
                    (new_indicator, new_type, new_category, new_risk)
                )
                db.commit()
                log_audit("ADD_THREAT", indicator=new_indicator)

        elif "indicator" in request.form:
            indicator = sanitize(request.form["indicator"])
            filter_type = request.form["filter_type"]

            if not indicator or len(indicator) > 500:
                result = "NOT_FOUND"
            else:
                detected_type = auto_detect_type(indicator)
                actual_type = detected_type if detected_type else filter_type

                if filter_type == "All":
                    cursor.execute("SELECT * FROM threats WHERE indicator=?", (indicator,))
                else:
                    cursor.execute(
                        "SELECT * FROM threats WHERE indicator=? AND type=?",
                        (indicator, filter_type)
                    )

                result = cursor.fetchone()

                # Dispatch queries in parallel using ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=3) as executor:
                    futures = {}
                    if actual_type == "IP":
                        futures["abuse"] = executor.submit(check_ip_abuseipdb, indicator)
                        futures["vt"] = executor.submit(check_ip_virustotal, indicator)
                        futures["otx"] = executor.submit(check_otx, indicator, "IP")
                    elif actual_type == "Domain":
                        futures["vt"] = executor.submit(check_domain_virustotal, indicator)
                        futures["otx"] = executor.submit(check_otx, indicator, "Domain")
                    elif actual_type == "Hash":
                        futures["vt"] = executor.submit(check_hash_virustotal, indicator)
                        futures["otx"] = executor.submit(check_otx, indicator, "Hash")

                    # Wait for results
                    abuse_data = futures["abuse"].result() if "abuse" in futures else None
                    vt_data = futures["vt"].result() if "vt" in futures else None
                    otx_data = futures["otx"].result() if "otx" in futures else None

                if result is None:
                    result = "NOT_FOUND"

    # Fetch final stats
    cursor.execute("SELECT COUNT(*) FROM threats")
    total_threats = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threats WHERE type='IP'")
    total_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threats WHERE type='Domain'")
    total_domains = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threats WHERE type='Hash'")
    total_hashes = cursor.fetchone()[0]

    # Calculate pagination params
    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    per_page = 10
    total_pages = (total_threats + per_page - 1) // per_page if total_threats > 0 else 1
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page

    cursor.execute("SELECT * FROM threats ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, offset))
    recent_threats = cursor.fetchall()

    # Timeline: IOC additions per day for last 30 days
    cursor.execute("""
        SELECT DATE(created_at) as day, COUNT(*) as count
        FROM threats
        WHERE created_at IS NOT NULL
          AND DATE(created_at) >= DATE('now', '-29 days')
        GROUP BY day
        ORDER BY day ASC
    """)
    timeline_rows = cursor.fetchall()
    timeline_labels = json.dumps([r[0] for r in timeline_rows])
    timeline_values = json.dumps([r[1] for r in timeline_rows])

    return render_template(
        "index.html",
        result=result,
        abuse_data=abuse_data,
        vt_data=vt_data,
        otx_data=otx_data,
        total_threats=total_threats,
        total_ips=total_ips,
        total_domains=total_domains,
        total_hashes=total_hashes,
        recent_threats=recent_threats,
        page=page,
        total_pages=total_pages,
        timeline_labels=timeline_labels,
        timeline_values=timeline_values
    )


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row and check_password_hash(row[2], password):
            user = User(id=row[0], username=row[1], role=row[3])
            login_user(user)
            log_audit("USER_LOGIN")
            return redirect(url_for("home"))
        flash("Invalid username or password")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    log_audit("USER_LOGOUT")
    logout_user()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required")
            return render_template("register.html")
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            flash("Username already exists")
            return render_template("register.html")
        hashed_password = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hashed_password, "analyst")
        )
        db.commit()
        log_audit(f"USER_REGISTERED (username: {username})")
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/edit/<int:threat_id>", methods=["GET", "POST"])
@login_required
def edit_threat(threat_id):
    db = get_db()
    cursor = db.cursor()

    if request.method == "POST":
        indicator = sanitize(request.form["indicator"])
        threat_type = request.form["type"]
        category = sanitize(request.form["category"])

        try:
            risk_score = int(request.form["risk_score"])
            if not 0 <= risk_score <= 100:
                risk_score = 0
        except ValueError:
            risk_score = 0

        cursor.execute(
            "UPDATE threats SET indicator=?, type=?, category=?, risk_score=? WHERE id=?",
            (indicator, threat_type, category, risk_score, threat_id)
        )
        db.commit()
        log_audit("UPDATE_THREAT", indicator=indicator)
        return redirect("/")

    cursor.execute("SELECT * FROM threats WHERE id=?", (threat_id,))
    threat = cursor.fetchone()

    return render_template("edit.html", threat=threat)


@app.route("/export")
@login_required
def export_csv():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM threats ORDER BY id DESC")
    threats = cursor.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "indicator", "type", "category", "risk_score"])
    for threat in threats:
        writer.writerow(threat)

    filename = f"threatintel-iocs-{date.today()}.csv"
    log_audit("EXPORT_CSV")

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/sync-feeds", methods=["POST"])
@login_required
def sync_feeds():
    """Endpoint for logged-in analysts to manually trigger OSINT feed synchronization."""
    try:
        count = sync_threat_feeds()
        flash(f"Threat feeds synchronized successfully! Imported {count} new indicators.", "success")
    except Exception as e:
        flash(f"Sync error: {e}", "danger")
    return redirect(url_for("home"))


# ── BULK IMPORT ROUTE ────────────────────────────────────────────────────────

@app.route("/import", methods=["POST"])
@login_required
def bulk_import():
    """Accept a textarea paste or file upload and batch-insert IOCs."""
    raw_text = request.form.get("ioc_text", "")
    uploaded_file = request.files.get("ioc_file")

    lines = []
    if uploaded_file and uploaded_file.filename:
        try:
            content = uploaded_file.read().decode("utf-8", errors="ignore")
            lines.extend(content.splitlines())
        except Exception:
            pass
    if raw_text.strip():
        lines.extend(raw_text.splitlines())

    db = get_db()
    cursor = db.cursor()
    counts = {"IP": 0, "Domain": 0, "Hash": 0}
    skipped = 0
    unrecognised = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        indicator = sanitize(parts[0]) if parts else ""
        if not indicator or len(indicator) > 500:
            unrecognised += 1
            continue

        ioc_type = None
        if len(parts) > 1 and parts[1] in ("IP", "Domain", "Hash"):
            ioc_type = parts[1]
        else:
            ioc_type = auto_detect_type(indicator)

        if not ioc_type:
            unrecognised += 1
            continue

        category = sanitize(parts[2]) if len(parts) > 2 and parts[2] else "Bulk Import"
        try:
            risk_score = int(parts[3]) if len(parts) > 3 else 50
            risk_score = max(0, min(100, risk_score))
        except (ValueError, IndexError):
            risk_score = 50

        cursor.execute("SELECT id FROM threats WHERE indicator = ?", (indicator,))
        if cursor.fetchone():
            skipped += 1
            continue

        cursor.execute(
            "INSERT INTO threats (indicator, type, category, risk_score) VALUES (?, ?, ?, ?)",
            (indicator, ioc_type, category, risk_score)
        )
        counts[ioc_type] += 1

    db.commit()
    total = sum(counts.values())
    log_audit(
        f"BULK_IMPORT | Added {total} "
        f"(IP:{counts['IP']} Domain:{counts['Domain']} Hash:{counts['Hash']}) "
        f"Skipped:{skipped} Unrecognised:{unrecognised}"
    )
    flash(
        f"Import complete! Added {total} indicators "
        f"({counts['IP']} IPs, {counts['Domain']} Domains, {counts['Hash']} Hashes). "
        f"Skipped {skipped} duplicates, {unrecognised} unrecognised.",
        "success"
    )
    return redirect(url_for("home"))


# ── ADMIN PANEL ROUTES ────────────────────────────────────────────────────────

@app.route("/admin")
@admin_required
def admin_panel():
    """Main admin control panel — users, API keys, and audit log."""
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC")
    users = cursor.fetchall()

    cursor.execute(
        "SELECT ak.id, ak.name, ak.key, ak.created_at, u.username "
        "FROM api_keys ak JOIN users u ON ak.user_id = u.id ORDER BY ak.id DESC"
    )
    api_keys = cursor.fetchall()

    audit_lines = []
    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            audit_lines = f.readlines()[-100:][::-1]
    except FileNotFoundError:
        audit_lines = []

    return render_template(
        "admin.html",
        users=users,
        api_keys=api_keys,
        audit_lines=audit_lines
    )


@app.route("/admin/promote/<int:user_id>", methods=["POST"])
@admin_required
def admin_promote(user_id):
    """Promote a user to admin role."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if row and row[0] != current_user.username:
        cursor.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
        db.commit()
        log_audit(f"PROMOTE_USER | username: {row[0]}")
        flash(f"User '{row[0]}' promoted to admin.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/demote/<int:user_id>", methods=["POST"])
@admin_required
def admin_demote(user_id):
    """Demote an admin to analyst role."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if row and row[0] != current_user.username:
        cursor.execute("UPDATE users SET role = 'analyst' WHERE id = ?", (user_id,))
        db.commit()
        log_audit(f"DEMOTE_USER | username: {row[0]}")
        flash(f"User '{row[0]}' demoted to analyst.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    """Permanently delete a user account and their API keys."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        flash("User not found.", "danger")
        return redirect(url_for("admin_panel"))
    if row[0] == current_user.username:
        flash("Cannot delete your own account.", "danger")
        return redirect(url_for("admin_panel"))
    cursor.execute("DELETE FROM api_keys WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    log_audit(f"DELETE_USER | username: {row[0]}")
    flash(f"User '{row[0]}' and their API keys deleted.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/generate-key", methods=["POST"])
@admin_required
def admin_generate_key():
    """Generate a new API key and assign it to a user."""
    key_name = sanitize(request.form.get("key_name", "API Key").strip())
    try:
        target_user_id = int(request.form.get("user_id", current_user.id))
    except (ValueError, TypeError):
        target_user_id = current_user.id

    new_key = generate_api_key()
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO api_keys (user_id, key, name) VALUES (?, ?, ?)",
        (target_user_id, new_key, key_name)
    )
    db.commit()
    log_audit(f"GENERATE_API_KEY | name: {key_name}")
    flash(f"API Key generated — copy it now (shown only once): {new_key}", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/revoke-key/<int:key_id>", methods=["POST"])
@admin_required
def admin_revoke_key(key_id):
    """Revoke (delete) an API key."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT name FROM api_keys WHERE id = ?", (key_id,))
    row = cursor.fetchone()
    if row:
        cursor.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        db.commit()
        log_audit(f"REVOKE_API_KEY | name: {row[0]}")
        flash(f"API Key '{row[0]}' revoked.", "success")
    return redirect(url_for("admin_panel"))


# ── REST API v1 ───────────────────────────────────────────────────────────────

def _api_error(message, code=400):
    return jsonify({"error": message, "status": code}), code


def _api_ok(data, code=200):
    return jsonify({"status": code, **data}), code


@app.route("/api/v1/iocs", methods=["GET"])
def api_list_iocs():
    """List IOCs with optional type filter and pagination. Requires X-API-Key."""
    auth_user = api_key_auth()
    if not auth_user:
        return _api_error("Invalid or missing X-API-Key header.", 401)

    ioc_type = request.args.get("type")
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    offset = (page - 1) * per_page

    db = get_db()
    cursor = db.cursor()

    if ioc_type and ioc_type in ("IP", "Domain", "Hash"):
        cursor.execute(
            "SELECT id, indicator, type, category, risk_score, created_at "
            "FROM threats WHERE type = ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (ioc_type, per_page, offset)
        )
        total = db.cursor().execute(
            "SELECT COUNT(*) FROM threats WHERE type = ?", (ioc_type,)
        ).fetchone()[0]
    else:
        cursor.execute(
            "SELECT id, indicator, type, category, risk_score, created_at "
            "FROM threats ORDER BY id DESC LIMIT ? OFFSET ?",
            (per_page, offset)
        )
        total = db.cursor().execute("SELECT COUNT(*) FROM threats").fetchone()[0]

    rows = cursor.fetchall()
    iocs = [
        {"id": r[0], "indicator": r[1], "type": r[2],
         "category": r[3], "risk_score": r[4], "created_at": r[5]}
        for r in rows
    ]
    return _api_ok({
        "iocs": iocs,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 1
    })


@app.route("/api/v1/ioc/<path:indicator>", methods=["GET"])
def api_get_ioc(indicator):
    """Look up a single IOC by its indicator value. Requires X-API-Key."""
    auth_user = api_key_auth()
    if not auth_user:
        return _api_error("Invalid or missing X-API-Key header.", 401)

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, indicator, type, category, risk_score, created_at "
        "FROM threats WHERE indicator = ?",
        (indicator,)
    )
    row = cursor.fetchone()
    if not row:
        return _api_error(f"Indicator '{indicator}' not found in registry.", 404)

    return _api_ok({"found": True, "ioc": {
        "id": row[0], "indicator": row[1], "type": row[2],
        "category": row[3], "risk_score": row[4], "created_at": row[5]
    }})


@app.route("/api/v1/ioc", methods=["POST"])
def api_create_ioc():
    """Create a new IOC via JSON payload. Requires X-API-Key."""
    auth_user = api_key_auth()
    if not auth_user:
        return _api_error("Invalid or missing X-API-Key header.", 401)

    data = request.get_json(silent=True)
    if not data:
        return _api_error("JSON body required.", 400)

    indicator = html.escape(str(data.get("indicator", "")).strip())
    ioc_type = data.get("type")
    category = html.escape(str(data.get("category", "API Import")).strip())
    try:
        risk_score = int(data.get("risk_score", 50))
        risk_score = max(0, min(100, risk_score))
    except (ValueError, TypeError):
        risk_score = 50

    if not indicator:
        return _api_error("'indicator' field is required.", 400)
    if ioc_type not in ("IP", "Domain", "Hash"):
        ioc_type = auto_detect_type(indicator)
    if not ioc_type:
        return _api_error(
            "Could not detect IOC type. Provide 'type': 'IP', 'Domain', or 'Hash'.", 400
        )

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM threats WHERE indicator = ?", (indicator,))
    if cursor.fetchone():
        return _api_error(f"Indicator '{indicator}' already exists.", 409)

    cursor.execute(
        "INSERT INTO threats (indicator, type, category, risk_score) VALUES (?, ?, ?, ?)",
        (indicator, ioc_type, category, risk_score)
    )
    db.commit()
    log_audit("API_CREATE_IOC", indicator=indicator)
    return _api_ok({"created": True, "ioc": {
        "id": cursor.lastrowid, "indicator": indicator, "type": ioc_type,
        "category": category, "risk_score": risk_score
    }}, 201)


@app.route("/api/v1/ioc/<int:ioc_id>", methods=["DELETE"])
def api_delete_ioc(ioc_id):
    """Delete an IOC by ID. Requires admin API key."""
    auth_user = api_key_auth()
    if not auth_user:
        return _api_error("Invalid or missing X-API-Key header.", 401)
    if auth_user.role != "admin":
        return _api_error("Admin API key required to delete IOCs.", 403)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT indicator FROM threats WHERE id = ?", (ioc_id,))
    row = cursor.fetchone()
    if not row:
        return _api_error(f"IOC id {ioc_id} not found.", 404)

    cursor.execute("DELETE FROM threats WHERE id = ?", (ioc_id,))
    db.commit()
    log_audit("API_DELETE_IOC", indicator=row[0])
    return _api_ok({"deleted": True, "id": ioc_id, "indicator": row[0]})


# ── BACKGROUND SCHEDULER ──────────────────────────────────────────────────────

# Initialize Background Scheduler
scheduler = BackgroundScheduler()
# Run feed sync job immediately on start, and repeat every 6 hours
scheduler.add_job(func=sync_threat_feeds, trigger="interval", hours=6)
scheduler.start()


if __name__ == "__main__":
    app.run(debug=False)