import streamlit as st
import sqlite3
import bcrypt
import datetime
import pandas as pd

# --------------------------
# ✅ Page Config & Branding
# --------------------------
st.set_page_config(page_title="Foulger Homes Maintenance", page_icon="🏠", layout="centered")
st.image("foulger_homes.png", width=150)
st.title("🏠 Foulger Homes Maintenance Portal")

# --------------------------
# ✅ Helper Functions
# --------------------------
def get_conn():
    return sqlite3.connect('maintenance.db')

def hash_pw(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_pw(password, hashed):
    if isinstance(hashed, str):
        hashed = hashed.encode('utf-8')
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# --------------------------
# ✅ DB Functions
# --------------------------
def register_tenant(unit, name, phone, password):
    conn = get_conn()
    c = conn.cursor()
    hashed = hash_pw(password)
    try:
        c.execute("""
            INSERT INTO tenants (unit_number, name, phone, password_hash)
            VALUES (?, ?, ?, ?)
        """, (unit, name, phone, hashed))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def auth_tenant(unit, password):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, password_hash FROM tenants WHERE unit_number = ?", (unit,))
    row = c.fetchone()
    conn.close()
    if row and check_pw(password, row[1]):
        return row[0]
    else:
        return None

def auth_admin(username, password):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM admin WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row and check_pw(password, row[0]):
        return True
    return False

def submit_request(tenant_id, description):
    conn = get_conn()
    c = conn.cursor()
    now = datetime.datetime.now().isoformat()
    c.execute("""
        INSERT INTO requests 
        (tenant_id, issue_description, priority, status, admin_notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (tenant_id, description, 'Normal', 'Submitted', '', now, now))
    conn.commit()
    conn.close()

def get_tenant_requests(tenant_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT id, issue_description, priority, status, admin_notes, created_at, updated_at
        FROM requests WHERE tenant_id = ?
    """, (tenant_id,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_all_requests():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT r.id, t.unit_number, t.name, r.issue_description,
               r.priority, r.status, r.admin_notes, r.created_at, r.updated_at
        FROM requests r 
        JOIN tenants t ON r.tenant_id = t.id
    """)
    rows = c.fetchall()
    conn.close()
    return rows

def update_request(req_id, priority, status, notes):
    conn = get_conn()
    c = conn.cursor()
    now = datetime.datetime.now().isoformat()
    c.execute("""
        UPDATE requests 
        SET priority = ?, status = ?, admin_notes = ?, updated_at = ?
        WHERE id = ?
    """, (priority, status, notes, now, req_id))
    conn.commit()
    conn.close()

# --------------------------
# ✅ Session State Init
# --------------------------
if 'role' not in st.session_state:
    st.session_state['role'] = None

# --------------------------
# ✅ Main Login Interface
# --------------------------
if st.session_state['role'] is None:
    st.markdown("### What would you like to do?")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📝 Register"):
            st.session_state.page = "register"
    with col2:
        if st.button("🔑 Tenant Login"):
            st.session_state.page = "tenant_login"
    with col3:
        if st.button("🗂️ Admin Login"):
            st.session_state.page = "admin_login"

    if 'page' in st.session_state:
        if st.session_state.page == "register":
            st.header("📝 Tenant Registration")
            unit = st.text_input("Unit Number")
            name = st.text_input("Name")
            phone = st.text_input("Phone")
            password = st.text_input("Password", type="password")
            if st.button("Register"):
                if register_tenant(unit, name, phone, password):
                    tenant_id = auth_tenant(unit, password)
                    st.session_state['role'] = 'tenant'
                    st.session_state['tenant_id'] = tenant_id
                    st.success("✅ Registered and logged in!")
                else:
                    st.error("❌ Unit number already exists.")

        elif st.session_state.page == "tenant_login":
            st.header("🔑 Tenant Login")
            unit = st.text_input("Unit Number")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                tenant_id = auth_tenant(unit, password)
                if tenant_id:
                    st.session_state['role'] = 'tenant'
                    st.session_state['tenant_id'] = tenant_id
                else:
                    st.error("❌ Invalid credentials.")

        elif st.session_state.page == "admin_login":
            st.header("🔐 Admin Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                if auth_admin(username, password):
                    st.session_state['role'] = 'admin'
                else:
                    st.error("❌ Invalid credentials.")

# --------------------------
# ✅ Tenant Dashboard
# --------------------------
elif st.session_state['role'] == 'tenant':
    st.header("👤 Tenant Dashboard")
    if st.button("Logout"):
        st.session_state['role'] = None

    st.subheader("Submit Maintenance Request")
    description = st.text_area("Describe the issue")
    if st.button("Submit Request"):
        submit_request(st.session_state['tenant_id'], description)
        st.success("✅ Request submitted!")

    st.subheader("Your Requests")
    data = get_tenant_requests(st.session_state['tenant_id'])
    columns = ["ID", "Issue", "Priority", "Status", "Admin Notes", "Created At", "Updated At"]
    df = pd.DataFrame(data, columns=columns)
    st.dataframe(df, use_container_width=True)

# --------------------------
# ✅ Admin Dashboard
# --------------------------
elif st.session_state['role'] == 'admin':
    st.header("📂 Admin Dashboard")
    if st.button("Logout"):
        st.session_state['role'] = None

    st.subheader("🗂️ Manage Requests")
    data = get_all_requests()
    for row in data:
        with st.expander(f"Request ID: {row[0]} | Unit: {row[1]} | Tenant: {row[2]} | Status: {row[5]}"):
            st.write(f"**Issue:** {row[3]}")
            notes = st.text_area(f"Admin Notes for ID {row[0]}", row[6])
            priority = st.selectbox(f"Priority for ID {row[0]}", ['Low', 'Normal', 'High'], index=['Low', 'Normal', 'High'].index(row[4]))
            status = st.selectbox(f"Status for ID {row[0]}", ['Submitted', 'In Progress', 'Completed'], index=['Submitted', 'In Progress', 'Completed'].index(row[5]))
            if st.button(f"Update ID {row[0]}"):
                update_request(row[0], priority, status, notes)
                st.success("✅ Updated!")

    st.subheader("📑 Reports")
    df = pd.DataFrame(data, columns=["ID", "Unit", "Tenant", "Issue", "Priority", "Status", "Admin Notes", "Created At", "Updated At"])
    st.dataframe(df, use_container_width=True)
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button("⬇️ Download All Requests as CSV", data=csv, file_name="requests_report.csv", mime='text/csv')


