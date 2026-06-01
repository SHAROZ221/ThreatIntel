import sqlite3

conn = sqlite3.connect("threats.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM threats")

rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()