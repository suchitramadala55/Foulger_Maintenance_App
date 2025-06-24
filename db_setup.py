
import sqlite3
import bcrypt

# Connect to DB
conn = sqlite3.connect('maintenance.db')
c = conn.cursor()

# Create tenants table
c.execute('''
    CREATE TABLE IF NOT EXISTS tenants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        unit_number TEXT UNIQUE,
        name TEXT,
        phone TEXT,
        password_hash TEXT
    )
''')

# Create requests table
c.execute('''
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id INTEGER,
        issue_description TEXT,
        priority TEXT,
        status TEXT,
        admin_notes TEXT,
        created_at TEXT,
        updated_at TEXT,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    )
''')

# Create admin table
c.execute('''
    CREATE TABLE IF NOT EXISTS admin (
        username TEXT PRIMARY KEY,
        password_hash TEXT
    )
''')

# Insert default admin (only if not exists)
def insert_admin():
    username = 'admin'
    password = 'admin123'  # default password — change later!
    c.execute("SELECT * FROM admin WHERE username = ?", (username,))
    if c.fetchone() is None:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT INTO admin (username, password_hash) VALUES (?, ?)", (username, hashed))
        conn.commit()

insert_admin()

print("Database and tables created. Default admin: admin/admin123")

conn.close()
