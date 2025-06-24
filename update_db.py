
import sqlite3

# Connect to your local database
conn = sqlite3.connect("maintenance.db")
c = conn.cursor()

# ✅ Add 'cost' column if not exists
try:
    c.execute("ALTER TABLE requests ADD COLUMN cost TEXT DEFAULT '';")
    print("✅ 'cost' column added successfully.")
except sqlite3.OperationalError as e:
    print("⚠️ It seems 'cost' column already exists or another error:", e)

# ✅ Check table structure
c.execute("PRAGMA table_info(requests);")
print("\nrequests table structure:")
for row in c.fetchall():
    print(row)

conn.commit()
conn.close()
