from flask import Flask, render_template, request, redirect, Response
import sqlite3
import requests
import csv
import io
from datetime import date
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")


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


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    abuse_data = None
    vt_data = None

    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()

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
            delete_id = request.form["delete_id"]
            cursor.execute("DELETE FROM threats WHERE id=?", (delete_id,))
            conn.commit()
            cursor.execute("SELECT * FROM threats ORDER BY id DESC")
            recent_threats = cursor.fetchall()

        elif "new_indicator" in request.form:
            new_indicator = request.form["new_indicator"]
            new_type = request.form["new_type"]
            new_category = request.form["new_category"]
            new_risk = request.form["new_risk"]
            cursor.execute(
                "INSERT INTO threats (indicator, type, category, risk_score) VALUES (?, ?, ?, ?)",
                (new_indicator, new_type, new_category, new_risk)
            )
            conn.commit()
            cursor.execute("SELECT * FROM threats ORDER BY id DESC")
            recent_threats = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) FROM threats")
            total_threats = cursor.fetchone()[0]

        elif "indicator" in request.form:
            indicator = request.form["indicator"]
            filter_type = request.form["filter_type"]

            if filter_type == "All":
                cursor.execute("SELECT * FROM threats WHERE indicator=?", (indicator,))
            else:
                cursor.execute(
                    "SELECT * FROM threats WHERE indicator=? AND type=?",
                    (indicator, filter_type)
                )

            result = cursor.fetchone()

            if filter_type in ("All", "IP"):
                abuse_data = check_ip_abuseipdb(indicator)
                vt_data = check_ip_virustotal(indicator)
            elif filter_type == "Domain":
                vt_data = check_domain_virustotal(indicator)
            elif filter_type == "Hash":
                vt_data = check_hash_virustotal(indicator)

            if result is None:
                result = "NOT_FOUND"

    conn.close()

    return render_template(
        "index.html",
        result=result,
        abuse_data=abuse_data,
        vt_data=vt_data,
        total_threats=total_threats,
        total_ips=total_ips,
        total_domains=total_domains,
        total_hashes=total_hashes,
        recent_threats=recent_threats
    )


@app.route("/edit/<int:threat_id>", methods=["GET", "POST"])
def edit_threat(threat_id):
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()

    if request.method == "POST":
        indicator = request.form["indicator"]
        threat_type = request.form["type"]
        category = request.form["category"]
        risk_score = request.form["risk_score"]
        cursor.execute(
            "UPDATE threats SET indicator=?, type=?, category=?, risk_score=? WHERE id=?",
            (indicator, threat_type, category, risk_score, threat_id)
        )
        conn.commit()
        conn.close()
        return redirect("/")

    cursor.execute("SELECT * FROM threats WHERE id=?", (threat_id,))
    threat = cursor.fetchone()
    conn.close()

    return render_template("edit.html", threat=threat)


@app.route("/export")
def export_csv():
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threats ORDER BY id DESC")
    threats = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "indicator", "type", "category", "risk_score"])
    for threat in threats:
        writer.writerow(threat)

    filename = f"threatintel-iocs-{date.today()}.csv"

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


if __name__ == "__main__":
    app.run(debug=False)