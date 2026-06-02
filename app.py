from flask import Flask, render_template, request
import sqlite3

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()

    # Dashboard Statistics
    cursor.execute("SELECT COUNT(*) FROM threats")
    total_threats = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threats WHERE type='IP'")
    total_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threats WHERE type='Domain'")
    total_domains = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threats WHERE type='Hash'")
    total_hashes = cursor.fetchone()[0]

    # Recent Threats
    cursor.execute("SELECT * FROM threats ORDER BY id DESC")
    recent_threats = cursor.fetchall()

    # Handle Forms
    if request.method == "POST":

        # Add New Threat Form
        if "new_indicator" in request.form:

            new_indicator = request.form["new_indicator"]
            new_type = request.form["new_type"]
            new_category = request.form["new_category"]
            new_risk = request.form["new_risk"]

            cursor.execute(
                """
                INSERT INTO threats
                (indicator, type, category, risk_score)
                VALUES (?, ?, ?, ?)
                """,
                (new_indicator, new_type, new_category, new_risk)
            )

            conn.commit()

            # Refresh threat list after insert
            cursor.execute("SELECT * FROM threats ORDER BY id DESC")
            recent_threats = cursor.fetchall()

            cursor.execute("SELECT COUNT(*) FROM threats")
            total_threats = cursor.fetchone()[0]

        # Search Form
        elif "indicator" in request.form:

            indicator = request.form["indicator"]
            filter_type = request.form["filter_type"]

            if filter_type == "All":

                cursor.execute(
                    "SELECT * FROM threats WHERE indicator=?",
                    (indicator,)
                )

            else:

                cursor.execute(
                    "SELECT * FROM threats WHERE indicator=? AND type=?",
                    (indicator, filter_type)
                )

            result = cursor.fetchone()

            if result is None:
                result = "NOT_FOUND"

    conn.close()

    return render_template(
        "index.html",
        result=result,
        total_threats=total_threats,
        total_ips=total_ips,
        total_domains=total_domains,
        total_hashes=total_hashes,
        recent_threats=recent_threats
    )

if __name__ == "__main__":
    app.run(debug=True)