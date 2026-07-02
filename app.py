from flask import Flask, render_template, request, redirect, Response, g, url_for, flash
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

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "threat_intel_secret_key_12345")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

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


def sanitize(value):
    """Secure sanitization using standard HTML escaping to prevent XSS."""
    return html.escape(value.strip())


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
def home():
    result = None
    abuse_data = None
    vt_data = None
    otx_data = None

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT COUNT(*) FROM threats")
    total_threats = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threats WHERE type='IP'")
    total_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threats WHERE type='Domain'")
    total_domains = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threats WHERE type='Hash'")
    total_hashes = cursor.fetchone()[0]

    cursor.execute("SELECT * FROM threats ORDER BY id DESC")
    recent_threats = cursor.fetchall()

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
            
            cursor.execute("SELECT * FROM threats ORDER BY id DESC")
            recent_threats = cursor.fetchall()

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

            cursor.execute("SELECT * FROM threats ORDER BY id DESC")
            recent_threats = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) FROM threats")
            total_threats = cursor.fetchone()[0]

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

                # Dispatch queries safely using the auto-detected or filtered type
                if actual_type == "IP":
                    abuse_data = check_ip_abuseipdb(indicator)
                    vt_data = check_ip_virustotal(indicator)
                    otx_data = check_otx(indicator, "IP")
                elif actual_type == "Domain":
                    vt_data = check_domain_virustotal(indicator)
                    otx_data = check_otx(indicator, "Domain")
                elif actual_type == "Hash":
                    vt_data = check_hash_virustotal(indicator)
                    otx_data = check_otx(indicator, "Hash")

                if result is None:
                    result = "NOT_FOUND"

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
        recent_threats=recent_threats
    )


@app.route("/login", methods=["GET", "POST"])
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


if __name__ == "__main__":
    app.run(debug=False)