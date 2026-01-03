import streamlit as st
import pandas as pd
import numpy as np
import time
import random
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import os
import binascii
import math
import streamlit.components.v1 as components

# --- Configuration & Setup ---
st.set_page_config(
    page_title="Q-SAFE: HYPERION",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- 3D Visual Core (Three.js) ---
def render_3d_core():
    html_code = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { margin: 0; overflow: hidden; background-color: transparent; }
            canvas { display: block; }
        </style>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    </head>
    <body>
        <div id="canvas-container"></div>
        <script>
            const container = document.getElementById('canvas-container');
            const scene = new THREE.Scene();
            
            // Camera
            const camera = new THREE.PerspectiveCamera(75, window.innerWidth / 300, 0.1, 1000);
            camera.position.z = 2.5;

            // Renderer
            const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
            renderer.setSize(window.innerWidth, 300);
            container.appendChild(renderer.domElement);

            // Objects
            // 1. Core Shield (Icosahedron)
            const geometry = new THREE.IcosahedronGeometry(1, 1);
            const material = new THREE.MeshBasicMaterial({ 
                color: 0x00ff41, 
                wireframe: true,
                transparent: true,
                opacity: 0.8
            });
            const shield = new THREE.Mesh(geometry, material);
            scene.add(shield);

            // 2. Inner Core (Sphere)
            const coreGeo = new THREE.SphereGeometry(0.5, 32, 32);
            const coreMat = new THREE.MeshBasicMaterial({ color: 0x00ff41 });
            const core = new THREE.Mesh(coreGeo, coreMat);
            scene.add(core);
            
            // 3. Particles
            const particlesGeo = new THREE.BufferGeometry();
            const particleCount = 200;
            const posArray = new Float32Array(particleCount * 3);
            for(let i = 0; i < particleCount * 3; i++) {
                posArray[i] = (Math.random() - 0.5) * 5;
            }
            particlesGeo.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
            const particlesMat = new THREE.PointsMaterial({
                size: 0.02,
                color: 0x00bcd4
            });
            const particles = new THREE.Points(particlesGeo, particlesMat);
            scene.add(particles);

            // Animation Loop
            function animate() {
                requestAnimationFrame(animate);

                shield.rotation.x += 0.002;
                shield.rotation.y += 0.005;
                
                core.scale.x = 1 + Math.sin(Date.now() * 0.005) * 0.1;
                core.scale.y = 1 + Math.sin(Date.now() * 0.005) * 0.1;
                core.scale.z = 1 + Math.sin(Date.now() * 0.005) * 0.1;

                particles.rotation.y -= 0.002;

                renderer.render(scene, camera);
            }
            animate();

            // Resize Handler
            window.addEventListener('resize', () => {
                camera.aspect = window.innerWidth / 300;
                camera.updateProjectionMatrix();
                renderer.setSize(window.innerWidth, 300);
            });
        </script>
    </body>
    </html>
    """
    components.html(html_code, height=300)

# --- Advanced Glassmorphism CSS ---
st.markdown("""
<style>
    /* Background & Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Rajdhani:wght@300;500;700&display=swap');
    
    .stApp {
        background: radial-gradient(circle at center, #111, #000);
        color: #e0e0e0;
        font-family: 'Rajdhani', sans-serif;
    }
    
    /* Headers */
    h1, h2, h3 {
        font-family: 'Orbitron', sans-serif;
        color: #fff;
        text-shadow: 0 0 10px rgba(0, 255, 65, 0.7);
    }
    
    /* Glassmorphism Cards */
    .glass-card {
        background: rgba(255, 255, 255, 0.03);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
        margin-bottom: 20px;
    }
    
    /* Metric Styling */
    div[data-testid="stMetricValue"] {
        color: #00ff41;
        font-family: 'Orbitron', sans-serif;
        font-size: 36px;
        text-shadow: 0 0 15px rgba(0, 255, 65, 0.4);
    }
    
    /* Custom Sidebar */
    section[data-testid="stSidebar"] {
        background: rgba(0, 0, 0, 0.8);
        border-right: 1px solid #333;
    }
    
    /* Inputs */
    .stTextInput > div > div > input {
        background-color: rgba(255,255,255,0.05);
        color: #fff;
        border: 1px solid #444;
    }
    
    /* Hex Box */
    .hex-display {
        background: rgba(0,0,0,0.6);
        color: #00ff41;
        font-family: 'Courier New', monospace;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #00ff41;
        box-shadow: inset 0 0 20px rgba(0,255,65,0.1);
        max-height: 400px;
        overflow-y: auto;
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background-color: transparent;
        gap: 20px;
    }
    .stTabs [data-baseweb="tab"] {
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.1);
        color: #aaa;
        border-radius: 8px;
        padding: 10px 20px;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, rgba(0,255,65,0.2), rgba(0,0,0,0));
        border: 1px solid #00ff41;
        color: #fff;
        box-shadow: 0 0 15px rgba(0,255,65,0.2);
    }
</style>
""", unsafe_allow_html=True)

# --- Logic & State ---
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []
if 'depth_log' not in st.session_state:
    st.session_state.depth_log = [150.0] * 50

# --- Helper Functions ---
@st.cache_data
def load_scan_targets(limit=100):
    default_targets = ["/etc/passwd", "/etc/hosts", "/proc/version", "/proc/meminfo"]
    if os.path.exists("scan_list.txt"):
        with open("scan_list.txt") as f:
            targets = [l.strip() for l in f.readlines() if l.strip()]
            return (targets + default_targets)[:limit]
    return default_targets

def get_file_stats(path):
    try:
        stat = os.stat(path)
        with open(path, "rb") as f:
            head = f.read(64)
        hexa = binascii.hexlify(head).decode()
        hexa_fmt = ' '.join(hexa[i:i+2] for i in range(0, len(hexa), 2))
        return stat.st_size, stat.st_mtime, hexa_fmt
    except:
        return 0, 0, "ACCESS DENIED"

# --- Main Layout ---

# 1. 3D Header Section
col_3d, col_title = st.columns([1, 2])
with col_3d:
    render_3d_core()
with col_title:
    st.markdown("<br><br>", unsafe_allow_html=True) # Spacer
    st.title("Q-SAFE: HYPERION")
    st.markdown("### AUTONOMOUS ICS DEFENSE SYSTEM")
    st.markdown("STATUS: **<span style='color:#00ff41'>SECURE</span>** | UPTIME: **42H 12M** | THREAT LEVEL: **LOW**", unsafe_allow_html=True)

st.write("") # Spacer

# 2. Glassmorphism Dashboard
targets = load_scan_targets()

with st.sidebar:
    st.header("🎮 COMMAND DECK")
    st.write("---")
    active_defense = st.toggle("ACTIVATE SHIELD", value=True)
    deep_scan = st.checkbox("DEEP HEURISTICS", value=False)
    target_select = st.selectbox("MANUAL TARGET", targets)
    st.write("---")
    st.info("System running in protected mode. Unauthorized access attempts will be logged.")

# Tabs
tab_ops, tab_intel, tab_forensics = st.tabs(["⚡ OPERATIONS", "📡 INTEL FEED", "🧬 FORENSICS"])

with tab_ops:
    # Metrics Container in Glass
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    m1, m2, m3, m4 = st.columns(4)
    
    # Sim Data
    depth = st.session_state.depth_log[-1] + random.uniform(-0.5, 0.5)
    depth = max(100, min(200, depth))
    st.session_state.depth_log.append(depth)
    if len(st.session_state.depth_log) > 50: st.session_state.depth_log.pop(0)
    
    m1.metric("WELL PRESSURE", f"{int(depth * 15)} PSI", "+12")
    m2.metric("FLUID DEPTH", f"{depth:.2f} m", "-0.1m")
    m3.metric("CORE TEMP", "42°C", "Stable")
    m4.metric("NETWORK LOAD", "1.2 GB/s", "+5%")
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Graphs in Glass
    c_graph, c_map = st.columns([2, 1])
    
    with c_graph:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("HYDRAULIC MONITORING")
        fig = px.area(
            y=st.session_state.depth_log, 
            labels={'y':'Depth (m)', 'x':'Time'},
        )
        fig.update_traces(line_color='#00ff41', fill_color='rgba(0, 255, 65, 0.1)')
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#ccc',
            height=300,
            margin=dict(l=0, r=0, t=10, b=0),
            xaxis=dict(visible=False),
            yaxis=dict(gridcolor='rgba(255,255,255,0.1)')
        )
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with c_map:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("SECTOR STATUS")
        # Radial Chart or similar
        fig_rad = go.Figure(go.Scatterpolar(
            r=[random.randint(60, 100) for _ in range(5)],
            theta=['PU-1', 'VALVE-A', 'SENS-X', 'NET-G', 'CORE'],
            fill='toself',
            line_color='#00bcd4'
        ))
        fig_rad.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            polar=dict(
                bgcolor='rgba(0,0,0,0)',
                radialaxis=dict(visible=False),
                angularaxis=dict(color='#888')
            ),
            font_color='#ccc',
            height=300,
            margin=dict(l=20, r=20, t=20, b=20)
        )
        st.plotly_chart(fig_rad, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

with tab_intel:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("LIVE THREAT INTELLIGENCE")
    
    df = pd.DataFrame({
        "TIMESTAMP": [datetime.now().strftime("%H:%M:%S") for _ in range(5)],
        "SOURCE IP": [f"192.168.1.{random.randint(10,99)}" for _ in range(5)],
        "VECTOR": random.choices(["Buffer Overflow", "XSS", "SQL Injection", "Port Scan"], k=5),
        "ACTION": ["BLOCKED"] * 5
    })
    
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )
    st.caption("Monitoring active channels: 0x88f - 0xff2")
    st.markdown('</div>', unsafe_allow_html=True)

with tab_forensics:
    col_file, col_hex = st.columns([1, 2])
    
    # File Details
    size, mtime, hexdump = get_file_stats(target_select)
    
    with col_file:
        st.markdown(f'<div class="glass-card"><h3>TARGET: {os.path.basename(target_select)}</h3>', unsafe_allow_html=True)
        st.info(f"PATH: {target_select}")
        st.write(f"SIZE: {size} bytes")
        st.write(f"MODIFIED: {datetime.fromtimestamp(mtime) if mtime else 'N/A'}")
        
        status = "SAFE" if size < 100000 else "SUSPICIOUS (SIZE)"
        st.write(f"AI ANALYSIS: **{status}**")
        st.progress(random.randint(80, 100) if status == "SAFE" else random.randint(20, 50))
        st.markdown('</div>', unsafe_allow_html=True)
        
    with col_hex:
        st.markdown("### MEMORY DUMP (FIRST 64 BYTES)")
        html_hex = f"""
        <div class="hex-display">
00000000  {hexdump[:48]}  |{'.' * 16}|
00000010  {hexdump[48:] if len(hexdump) > 48 else ''} ...
        </div>
        """
        st.markdown(html_hex, unsafe_allow_html=True)
        st.warning("Authorized Personnel Only. Artifact usage is logged.")

# Auto Refresh
time.sleep(1)
st.rerun()
