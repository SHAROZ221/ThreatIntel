"""
ThreatIntel Database Migration
Run once to upgrade an existing threats.db to the new schema.
Safe to re-run — uses IF NOT EXISTS and catches duplicate-column errors.
"""
import sqlite3

DATABASE = "threats.db"


def migrate():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("Running ThreatIntel database migration...")

    # 1. Add created_at to threats table (NULL first, then backfill)
    try:
        cursor.execute(
            "ALTER TABLE threats ADD COLUMN created_at DATETIME"
        )
        cursor.execute(
            "UPDATE threats SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"
        )
        print("  [OK] Added created_at to threats table")
    except Exception as e:
        print(f"  [--] threats.created_at: {e}")

    # 2. Add created_at to users table (NULL first, then backfill)
    try:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN created_at DATETIME"
        )
        cursor.execute(
            "UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"
        )
        print("  [OK] Added created_at to users table")
    except Exception as e:
        print(f"  [--] users.created_at: {e}")

    # 3. Create api_keys table
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
    print("  [OK] Ensured api_keys table exists")

    conn.commit()
    conn.close()
    print("\nMigration complete! Restart app.py to use the new features.")


if __name__ == "__main__":
    migrate()
