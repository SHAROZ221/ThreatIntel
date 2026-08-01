import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("threats.db")
cursor = conn.cursor()

# Create threats table (with created_at timestamp)
cursor.execute("""
CREATE TABLE IF NOT EXISTS threats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator   TEXT NOT NULL,
    type        TEXT NOT NULL,
    category    TEXT NOT NULL,
    risk_score  INTEGER NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# Create users table (with created_at timestamp)
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT DEFAULT 'analyst',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# Create api_keys table
cursor.execute("""
CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    key         TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL DEFAULT 'Default Key',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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