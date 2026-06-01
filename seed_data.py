import sqlite3

conn = sqlite3.connect("threats.db")
cursor = conn.cursor()

sample_threats = [
    ("185.220.101.1", "IP", "Malware", 95),
    ("malicious-site.com", "Domain", "Phishing", 90),
    ("e99a18c428cb38d5f260853678922e03", "Hash", "Trojan", 85)
]

cursor.executemany(
    "INSERT INTO threats (indicator, type, category, risk_score) VALUES (?, ?, ?, ?)",
    sample_threats
)

conn.commit()
conn.close()

print("Sample threat data added!")