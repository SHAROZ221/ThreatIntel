import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("threats.db")
cursor = conn.cursor()

# Create threats table
cursor.execute("""
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    type TEXT NOT NULL,
    category TEXT NOT NULL,
    risk_score INTEGER NOT NULL
)
""")

# Create users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'analyst'
)
""")

# Seed default admin user if not already present
cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
if cursor.fetchone() is None:
    hashed_password = generate_password_hash("admin123")
    cursor.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("admin", hashed_password, "admin")
    )
    print("Seeded default admin account (username: admin, password: admin123)")

conn.commit()
conn.close()

print("Database initialized successfully!")