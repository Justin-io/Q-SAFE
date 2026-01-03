import streamlit as st
import pandas as pd
import numpy as np
import time
import random
import os

# --- Configuration & Setup ---
st.set_page_config(
    page_title="Q-SAFE: IRON SENTINEL",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for "Premium" Industrial Look
st.markdown("""
<style>
    .reportview-container {
        background: #0e1117;
    }
    .main {
        color: #00ff41; /* Hacker Green */
    }
    h1, h2, h3 {
        color: #e0e0e0;
        font-family: 'Roboto Mono', monospace;
    }
    .stButton>button {
        color: #000;
        background-color: #00ff41;
        border: none;
        font-weight: bold;
    }
    .stDataFrame {
        border: 1px solid #333;
    }
    .metric-card {
        background-color: #1f2937;
        padding: 15px;
        border-radius: 5px;
        border-left: 4px solid #00ff41;
    }
</style>
""", unsafe_allow_html=True)

# --- Logic ---

@st.cache_data
def load_scan_targets(filepath="scan_list.txt"):
    """Loads targets from the scan list."""
    if not os.path.exists(filepath):
        # Fallback if file is missing
        return [f"/sys/kernel/register_0x{i:04X}" for i in range(1000)]
    
    with open(filepath, "r") as f:
        # Read first 1000 lines for performance
        return [line.strip() for line in f.readlines()[:5000]]

class SystemState:
    def __init__(self):
        self.well_depth = 124.5 # Meters
        self.pressure = 2400 # PSI
        self.pump_active = True
        self.alert_active = False

    def update(self):
        # Simulate physics
        if self.pump_active:
            self.well_depth += random.uniform(-0.1, 0.05) # Removing fluid, depth varies? 
            # Actually, "Well Depth" usually means depth to fluid surface. Pumping lowers surface => depth increases.
            self.well_depth += random.uniform(0.01, 0.05)
        else:
            self.well_depth -= random.uniform(0.01, 0.05) # Recovering
        
        # Clip
        self.well_depth = max(100.0, min(self.well_depth, 150.0))
        
        # Pressure fluctuation
        self.pressure = 2400 + np.sin(time.time()) * 50 + random.uniform(-10, 10)

def simulate_register_value():
    """Generates a realistic hex register value."""
    return f"0x{random.getrandbits(32):08X}"

def check_integrity(file_path):
    """Simulates a check on the file/register."""
    return "OK" if random.random() > 0.05 else "ANOMALY"

# --- UI Layout ---

st.title("🛡️ Q-SAFE: IRON SENTINEL")
st.markdown("**Real-Time Industrial Control System Monitor & CFI Guard**")

col1, col2 = st.columns([1, 2])

# Sidebar Controls
with st.sidebar:
    st.header("⚙️ Control Panel")
    
    scan_active = st.toggle("Enable Active Scanning", value=True)
    pump_toggle = st.toggle("Hydraulic Pump A", value=True)
    
    st.divider()
    
    st.subheader("Threshold Configuration")
    max_depth = st.slider("Max Safe Well Depth (m)", 100.0, 200.0, 140.0)
    
    if st.button("TRIGGER MASS PUSH FIX", type="primary"):
        st.toast("Git Ignore Updated. Large files excluded.", icon="✅")
        # In a real app, this would run the git logic. We already did it.

# Load Data
targets = load_scan_targets()

# Session State for Physics
if 'system' not in st.session_state:
    st.session_state.system = SystemState()

# Update Physics
st.session_state.system.pump_active = pump_toggle
st.session_state.system.update()
sys = st.session_state.system

with col1:
    st.subheader("📊 Well Telemetry")
    
    # Live Metrics
    m1, m2 = st.columns(2)
    m1.metric("Well Depth", f"{sys.well_depth:.2f} m", f"{(sys.well_depth - 124.5):.2f}")
    m2.metric("Manifold Pressure", f"{int(sys.pressure)} PSI", f"{int(sys.pressure - 2400)}")
    
    # Alert Logic
    if sys.well_depth > max_depth:
        st.error(f"CRITICAL: DEPTH EXCEEDS LIMIT ({max_depth}m)!")
    elif not scan_active:
        st.warning("SECURITY SCANNER DISABLED")
    else:
        st.success("SYSTEM OPTIMAL")

    # Chart
    # We need to keep history for the chart
    if 'depth_history' not in st.session_state:
        st.session_state.depth_history = [124.5] * 50
    
    st.session_state.depth_history.append(sys.well_depth)
    if len(st.session_state.depth_history) > 100:
        st.session_state.depth_history.pop(0)
        
    chart_data = pd.DataFrame({
        "Depth (m)": st.session_state.depth_history
    })
    st.line_chart(chart_data, color="#00ff41", height=250)

with col2:
    st.subheader("🔍 Register Integrity Scan")
    
    if scan_active:
        # Simulate scanning a batch
        scan_batch_size = 15
        start_idx = random.randint(0, len(targets) - scan_batch_size)
        batch = targets[start_idx : start_idx + scan_batch_size]
        
        data = []
        for target in batch:
            val = simulate_register_value()
            status = check_integrity(target)
            data.append({
                "Target / Register": target[-40:] if len(target)>40 else target, # Truncate for UI
                "Current Value": val,
                "Integrity": status
            })
            
        df = pd.DataFrame(data)
        
        # Conditional Formatting via Pandas Styler not fully supported in simple dataframe view easily
        # but we can use st.dataframe with column config if desired, or simpler:
        
        st.dataframe(
            df, 
            column_config={
                "Integrity": st.column_config.TextColumn(
                    "Status",
                    help="Integrity Check Result",
                    validate="^OK$",
                )
            },
            hide_index=True,
            use_container_width=True 
        )
        
        if "ANOMALY" in [d["Integrity"] for d in data]:
             st.toast("Anomaly Detected in Register Bank!", icon="🚨")

    else:
        st.info("Scanner Paused. System Blind.")

# Auto-refresh loop trick for Streamlit
time.sleep(1) # Refresh rate
st.rerun()
