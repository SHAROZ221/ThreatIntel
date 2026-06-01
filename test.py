import sqlite3

conn = sqlite3.connect("test.db")
print("SQLite is working!")

conn.close()
