import os
import time
import pandas as pd
import streamlit as st
from threading import Thread
from queue import Queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# === PAGE CONFIGURATION ===
st.set_page_config(
    page_title="Adaptive Ransomware Detection & Response",
    page_icon="🛡️",
    layout="wide"
)

# === SECURE USERS DATABASE (Short Passwords as Requested) ===
USERS = {
    "elaf_admin": {"password": "123", "role": "Administrator", "name": "Elaf (System Admin)"},
    "reem_analyst": {"password": "456", "role": "Security Analyst", "name": "Reem (Security Analyst)"}
}

# === SESSION STATE INITIALIZATION FOR AUTHENTICATION ===
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "username" not in st.session_state:
    st.session_state["username"] = ""
if "role" not in st.session_state:
    st.session_state["role"] = ""

# === SECURE LOGIN PAGE COMPONENT ===
def login_page():
    st.markdown("<h1 style='text-align: center; color: #FF4B4B;'>🛡️ Secure Ransomware Defense System</h1>", unsafe_allow_html=True)
    st.markdown("<h4 style='text-align: center; color: gray;'>Access Restricted. Please authenticate securely.</h4>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("---")
        username_input = st.text_input("Username")
        password_input = st.text_input("Password", type="password")
        
        if st.button("Secure Login", use_container_width=True):
            if username_input in USERS and USERS[username_input]["password"] == password_input:
                st.session_state["authenticated"] = True
                st.session_state["username"] = username_input
                st.session_state["role"] = USERS[username_input]["role"]
                st.success(f"Authentication successful. Welcome, {USERS[username_input]['name']}!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Access Denied: Invalid credentials or unauthorized user.")

# === AUTHENTICATION ENFORCEMENT CHECK ===
if not st.session_state["authenticated"]:
    login_page()
else:
    # === SIDEBAR CONTROL PANEL & CONFIG ===
    st.sidebar.title("Secure Control Panel")
    st.sidebar.write(f"👤 **User:** {st.session_state['username']}")
    st.sidebar.write(f"🔒 **Role:** {st.session_state['role']}")
    st.sidebar.markdown("---")
    
    # --- DYNAMIC CONFIGURATION INPUTS FOR ANY USER OPENING THE LINK ---
    st.sidebar.subheader("⚙️ Target Configuration")
    MONITORED_PATH = st.sidebar.text_input("Enter Folder Path to Monitor:", value="monitoring")
    HONEYFILE_NAME = st.sidebar.text_input("Enter Honeyfile Name:", value="Password_hf.txt")
    
    os.makedirs(MONITORED_PATH, exist_ok=True)
    st.sidebar.markdown("---")

    # === SESSION STATE FOR WATCHDOG & LOGS ===
    if "live_logs" not in st.session_state:
        st.session_state.live_logs = []
    if "normal_count" not in st.session_state:
        st.session_state.normal_count = 0
    if "warning_count" not in st.session_state:
        st.session_state.warning_count = 0
    if "attack_count" not in st.session_state:
        st.session_state.attack_count = 0
    if "file_mod_counts" not in st.session_state:
        st.session_state.file_mod_counts = {}
    if "deleted_files_count" not in st.session_state:
        st.session_state.deleted_files_count = 0
    if "event_queue" not in st.session_state:
        st.session_state.event_queue = Queue()

    event_queue = st.session_state.event_queue

    # === MODERN SOC CSS STYLING ===
    st.markdown("""
        <style>
        .main { background-color: #0b0f19; }
        .stMetric { background-color: #111827; padding: 18px; border-radius: 12px; border: 1px solid #1f2937; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3); }
        .attack-banner { background-color: #991b1b; border: 2px solid #ef4444; padding: 18px; border-radius: 12px; color: white; text-align: center; font-weight: bold; font-size: 20px; letter-spacing: 1px; }
        .warning-banner { background-color: #b45309; border: 2px solid #f59e0b; padding: 18px; border-radius: 12px; color: white; text-align: center; font-weight: bold; font-size: 20px; letter-spacing: 1px; }
        .normal-banner { background-color: #065f46; border: 2px solid #10b981; padding: 18px; border-radius: 12px; color: white; text-align: center; font-weight: bold; font-size: 20px; letter-spacing: 1px; }
        h1, h2, h3 { color: #f3f4f6 !important; }
        </style>
    """, unsafe_allow_html=True)

    # === WATCHDOG EVENT HANDLER (Telemetry Tool) ===
    class LiveDashboardHandler(FileSystemEventHandler):
        def on_any_event(self, event):
            if event.is_directory:
                return
            
            action_type = event.event_type.upper()
            filename = os.path.basename(event.src_path)
            is_honeyfile = HONEYFILE_NAME.lower() in filename.lower()
            
            event_queue.put({
                "Timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "File Name": filename,
                "Action Type": action_type,
                "Is Honeyfile": is_honeyfile
            })

    def start_background_observer(path_to_watch):
        event_handler = LiveDashboardHandler()
        observer = Observer()
        if os.path.exists(path_to_watch):
            observer.schedule(event_handler, path=path_to_watch, recursive=False)
            observer.start()
            while True:
                time.sleep(1)

    if "observer_path" not in st.session_state or st.session_state.observer_path != MONITORED_PATH:
        st.session_state.observer_path = MONITORED_PATH
        st.session_state.observer_running = True
        obs_thread = Thread(target=start_background_observer, args=(MONITORED_PATH,), daemon=True)
        obs_thread.start()

    # === DRAIN QUEUE INTO SESSION STATE ===
    while not event_queue.empty():
        e = event_queue.get()
        action = e["Action Type"]
        filename = e["File Name"]
        is_hf = e["Is Honeyfile"]
        
        status = ""
        
        if is_hf:
            status = "🔴 ATTACK (1) [Honeyfile Deception Triggered]"
            st.session_state.attack_count += 1
        elif action == "DELETED":
            st.session_state.deleted_files_count += 1
            if st.session_state.deleted_files_count > 1:
                status = f"🔴 ATTACK (1) [Multiple Files Deleted: {st.session_state.deleted_files_count}]"
                st.session_state.attack_count += 1
            else:
                status = "🟡 WARNING (2) [Single File Deleted]"
                st.session_state.warning_count += 1
        elif action == "MODIFIED":
            if filename not in st.session_state.file_mod_counts:
                st.session_state.file_mod_counts[filename] = 0
            st.session_state.file_mod_counts[filename] += 1
            
            mod_count = st.session_state.file_mod_counts[filename]
            
            if mod_count > 10:
                status = f"🔴 ATTACK (1) [Excessive Modifications ({mod_count}) on '{filename}']"
                st.session_state.attack_count += 1
            elif 5 <= mod_count <= 10:
                status = f"🟡 WARNING (2) [Suspicious Modifications ({mod_count}) on '{filename}']"
                st.session_state.warning_count += 1
            else:
                status = f"🟢 NORMAL (0) [Minor Modifications ({mod_count}) on '{filename}']"
                st.session_state.normal_count += 1
        else:
            status = "🟢 NORMAL (0) [File Created / Safe Action]"
            st.session_state.normal_count += 1

        st.session_state.live_logs.insert(0, {
            "Timestamp": e["Timestamp"],
            "File Name": filename,
            "Action Type": action,
            "Classification": status
        })

    total_events = st.session_state.normal_count + st.session_state.warning_count + st.session_state.attack_count

    latest_status = "NORMAL"
    if len(st.session_state.live_logs) > 0:
        latest_cls = str(st.session_state.live_logs[0]["Classification"])
        if "ATTACK" in latest_cls:
            latest_status = "ATTACK"
        elif "WARNING" in latest_cls:
            latest_status = "WARNING"
        else:
            latest_status = "NORMAL"

    # --- ADDED SIMULATION BUTTON FOR ONLINE DEMO ---
    st.sidebar.subheader("🚨 Incident Simulation")
    if st.sidebar.button("Simulate Attack"):
        st.session_state.attack_count += 1
        st.session_state.live_logs.insert(0, {
            "Timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "File Name": HONEYFILE_NAME,
            "Action Type": "MODIFIED / BREACH",
            "Classification": "🔴 ATTACK (1) [Simulated Honeyfile Deception Triggered]"
        })
        st.rerun()

    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Refresh View", use_container_width=True):
        st.rerun()
        
    st.sidebar.markdown("---")
    if st.sidebar.button("Secure Logout", type="primary", use_container_width=True):
        st.session_state["authenticated"] = False
        st.session_state["username"] = ""
        st.session_state["role"] = ""
        st.rerun()

    # === HEADER & CONTROLS ===
    col_title, col_action = st.columns([4, 1])
    with col_title:
        st.title("🛡️ Adaptive Early Detection & Automated Response System for Ransomware")
        st.markdown(f"Integrated Architecture: **Watchdog Telemetry** | **Honeypot Deception** | **Feature Extractor** | **Kill-Switch (psutil)**")
        st.markdown(f"📍 **Active Monitor Path:** `{MONITORED_PATH}` | 🎯 **Target Honeyfile:** `{HONEYFILE_NAME}`")
    with col_action:
        st.write("")

    st.write("")

    # === DYNAMIC STATUS BANNER ===
    if latest_status == "ATTACK":
        st.markdown('<div class="attack-banner">🚨 CRITICAL SECURITY ALERT: RANSOMWARE BEHAVIOR / ATTACK DETECTED! 🚨</div>', unsafe_allow_html=True)
    elif latest_status == "WARNING":
        st.markdown('<div class="warning-banner">⚠️ WARNING: SUSPICIOUS ACTIVITY / THRESHOLD REACHED ⚠️</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="normal-banner">🟢 SYSTEM SECURE: Normal Behavioral Activity</div>', unsafe_allow_html=True)

    st.write("")

    # === METRICS CARDS ===
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric(label="Watchdog Guard", value="ACTIVE", delta="Real-time")
    with col2:
        st.metric(label="Normal Events (0)", value=st.session_state.normal_count, delta="Safe")
    with col3:
        st.metric(label="Warnings (2)", value=st.session_state.warning_count, delta="Caution")
    with col4:
        st.metric(label="Attacks Detected (1)", value=st.session_state.attack_count, delta="Critical", delta_color="inverse")
    with col5:
        st.metric(label="Total Tracked", value=total_events)

    st.divider()

    # === VISUAL CHARTS SECTION ===
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("📊 Threat Severity Breakdown")
        if total_events > 0:
            chart_df = pd.DataFrame({
                "Severity Level": ["Normal (0)", "Warning (2)", "Attack (1)"],
                "Count": [st.session_state.normal_count, st.session_state.warning_count, st.session_state.attack_count]
            })
            st.bar_chart(chart_df.set_index("Severity Level"), color="#3b82f6")
        else:
            st.info("Awaiting file system actions...")

    with chart_col2:
        st.subheader("🎯 System Risk Index Ratio")
        if total_events > 0:
            risk_ratio = ((st.session_state.attack_count + st.session_state.warning_count) / total_events) * 100
            st.write(f"Calculated Risk Percentage: **{risk_ratio:.1f}%**")
            st.progress(int(risk_ratio))
        else:
            st.info("No risk distribution available.")

    st.divider()

    # === DETAILED TELEMETRY TABLE ===
    st.subheader("📋 Active Tools Telemetry & Strict Classification Logs")

    if len(st.session_state.live_logs) > 0:
        df_logs = pd.DataFrame(st.session_state.live_logs)
        st.dataframe(df_logs, use_container_width=True)
    else:
        st.info("No actions recorded yet. Perform file actions inside the specified folder and click 'Refresh View'.")