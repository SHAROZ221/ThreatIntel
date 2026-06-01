import sqlite3

conn = sqlite3.connect("threats.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    type TEXT NOT NULL,
    category TEXT NOT NULL,
    risk_score INTEGER NOT NULL
)
""")

conn.commit()
conn.close()

print("Database created successfully!")