from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    result = ""

    if request.method == "POST":
        indicator = request.form["indicator"]

        conn = sqlite3.connect("threats.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM threats WHERE indicator=?",
            (indicator,)
        )

        threat = cursor.fetchone()

        conn.close()

        if threat:
            result = f"""
            Indicator: {threat[1]}<br>
            Type: {threat[2]}<br>
            Category: {threat[3]}<br>
            Risk Score: {threat[4]}
            """
        else:
            result = "No threat found."

    return f"""
    <h1>Threat Intelligence Aggregator</h1>

    <form method="POST">
        <input type="text" name="indicator" placeholder="Enter IP, Domain, or Hash">
        <button type="submit">Search</button>
    </form>

    <br>

    {result}
    """

if __name__ == "__main__":
    app.run(debug=True)