# ✅ IMPORTANT: Before running, update your database to add 'cost' column
# Run this SQL manually once:
# ALTER TABLE requests ADD COLUMN cost TEXT DEFAULT '';

import streamlit as st
import sqlite3
import bcrypt
import datetime
import pandas as pd

st.set_page_config(page_title="Foulger Homes Maintenance", page_icon="🏠", layout="centered")
st.image("foulger_homes.png", width=150)
st.title("🏠 Foulger Homes Maintenance Portal")

def get_conn():
    return sqlite3.connect('maintenance.db')

def hash_pw(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_pw(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

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
        (tenant_id, issue_description, priority, status, admin_notes, created_at, updated_at, cost)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (tenant_id, description, 'Normal', 'Submitted', '', now, now, ''))
    conn.commit()
    conn.close()

def get_tenant_requests(tenant_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT id, issue_description, priority, status, admin_notes, cost, created_at, updated_at
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
               r.priority, r.status, r.admin_notes, r.cost, r.created_at
        FROM requests r 
        JOIN tenants t ON r.tenant_id = t.id
    """)
    rows = c.fetchall()
    conn.close()
    return rows

def update_request(req_id, priority, status, notes, cost):
    conn = get_conn()
    c = conn.cursor()
    now = datetime.datetime.now().isoformat()
    c.execute("""
        UPDATE requests 
        SET priority = ?, status = ?, admin_notes = ?, cost = ?, updated_at = ?
        WHERE id = ?
    """, (priority, status, notes, cost, now, req_id))
    conn.commit()
    conn.close()

def reset_tenant_password(unit, phone, new_password):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM tenants WHERE unit_number = ? AND phone = ?", (unit, phone))
    row = c.fetchone()
    if row:
        hashed = hash_pw(new_password)
        c.execute("UPDATE tenants SET password_hash = ? WHERE id = ?", (hashed, row[0]))
        conn.commit()
        conn.close()
        return True
    else:
        conn.close()
        return False

# ✅ State
if 'role' not in st.session_state:
    st.session_state['role'] = None
if 'page' not in st.session_state:
    st.session_state['page'] = "register"

# ✅ Login / Register / Reset Password
if st.session_state['role'] is None:
    st.subheader("What would you like to do?")
    col1, col2, col3, col4 = st.columns(4)
    with col1:  st.button("📝 Tenant Register", on_click=lambda: st.session_state.update(page="register"))
    with col2:  st.button("🔑 Tenant Login", on_click=lambda: st.session_state.update(page="tenant_login"))
    with col3:  st.button("🔐 Admin Login", on_click=lambda: st.session_state.update(page="admin_login"))
    with col4:  st.button("🔓 Reset Password", on_click=lambda: st.session_state.update(page="reset_password"))

    page = st.session_state['page']
    if page == "register":
        st.header("📝 Tenant Registration")
        unit = st.text_input("Unit Number")
        name = st.text_input("Name")
        phone = st.text_input("Phone")
        password = st.text_input("Password", type="password")
        if st.button("Register"):
            if register_tenant(unit, name, phone, password):
                st.session_state['role'] = 'tenant'
                st.session_state['tenant_id'] = auth_tenant(unit, password)
                st.success("✅ Registered and logged in!")
            else:
                st.error("❌ Unit already exists.")
    elif page == "tenant_login":
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
    elif page == "admin_login":
        st.header("🔐 Admin Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if auth_admin(username, password):
                st.session_state['role'] = 'admin'
            else:
                st.error("❌ Invalid credentials.")
    elif page == "reset_password":
        st.header("🔓 Reset Tenant Password")
        unit = st.text_input("Unit Number")
        phone = st.text_input("Phone")
        new_pw = st.text_input("New Password", type="password")
        if st.button("Reset Password"):
            if reset_tenant_password(unit, phone, new_pw):
                st.success("✅ Password reset successfully!")
            else:
                st.error("❌ No match found.")

# ✅ Tenant Dashboard
elif st.session_state['role'] == 'tenant':
    st.header("👤 Tenant Dashboard")
    if st.button("Logout"):
        st.session_state['role'] = None; st.session_state['page'] = "register"

    st.subheader("Submit Maintenance Request")
    description = st.text_area("Describe the issue")
    if st.button("Submit Request"):
        submit_request(st.session_state['tenant_id'], description)
        st.success("✅ Request submitted!")

    st.subheader("Your Requests")
    df = pd.DataFrame(get_tenant_requests(st.session_state['tenant_id']),
                      columns=["ID", "Issue", "Priority", "Status", "Admin Notes", "Cost", "Created At", "Updated At"])
    st.dataframe(df, use_container_width=True)

# ✅ Admin Dashboard with Cost
elif st.session_state['role'] == 'admin':
    st.header("📂 Admin Dashboard")
    tab1, tab2 = st.tabs(["🗂️ Manage Requests", "📑 Reports"])
    with tab1:
        data = get_all_requests()
        for row in data:
            with st.expander(f"Request ID: {row[0]} | Unit: {row[1]} | Tenant: {row[2]} | Status: {row[5]}"):
                st.write(f"**Issue:** {row[3]}")
                notes = st.text_area(f"Admin Notes for ID {row[0]}", row[6])
                cost = st.text_input(f"Cost for ID {row[0]}", row[7])
                priority = st.selectbox(f"Priority for ID {row[0]}", ['Low','Normal','High'], index=['Low','Normal','High'].index(row[4]))
                status = st.selectbox(f"Status for ID {row[0]}", ['Submitted','In Progress','Completed'], index=['Submitted','In Progress','Completed'].index(row[5]))
                if st.button(f"Update ID {row[0]}"):
                    update_request(row[0], priority, status, notes, cost)
                    st.success("✅ Updated!")

    with tab2:
        st.subheader("📑 Reports & CSV Download")
        unit_filter = st.text_input("Filter by Unit Number")
        conn = get_conn()
        c = conn.cursor()
        if unit_filter:
            c.execute("""
                SELECT r.id, t.unit_number, t.name, r.issue_description,
                       r.priority, r.status, r.admin_notes, r.cost, r.created_at, r.updated_at
                FROM requests r 
                JOIN tenants t ON r.tenant_id = t.id
                WHERE t.unit_number = ?
            """, (unit_filter,))
        else:
            c.execute("""
                SELECT r.id, t.unit_number, t.name, r.issue_description,
                       r.priority, r.status, r.admin_notes, r.cost, r.created_at, r.updated_at
                FROM requests r 
                JOIN tenants t ON r.tenant_id = t.id
            """)
        rows = c.fetchall()
        conn.close()
        if rows:
            df = pd.DataFrame(rows, columns=["ID","Unit","Name","Issue","Priority","Status","Admin Notes","Cost","Created At","Updated At"])
            st.dataframe(df, use_container_width=True)
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download CSV", csv, "maintenance_report.csv", "text/csv")
        else:
            st.info("No data found.")

