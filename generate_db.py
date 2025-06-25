
import sqlite3

# Create or overwrite maintenance.db
conn = sqlite3.connect("maintenance.db")
c = conn.cursor()

# Tenants table
c.execute("""
CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unit_number TEXT NOT NULL,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL
)
""")

# Admin table with hashed password
c.execute("""
CREATE TABLE IF NOT EXISTS admin (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
)
""")

# Requests table
c.execute("""
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    issue_description TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL,
    priority TEXT,
    admin_notes TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
)
""")

# Insert default admin user (username: admin, password: admin123)
c.execute("INSERT OR IGNORE INTO admin (username, password_hash) VALUES (?, ?)", ('admin', 'admin123'))

conn.commit()
conn.close()
print("✅ New maintenance.db created successfully.")
