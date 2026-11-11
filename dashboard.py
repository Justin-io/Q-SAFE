"""Optional, honest Streamlit front-end for the Q-SAFE static scanner."""
from pathlib import Path
import streamlit as st
import pandas as pd
from q_safe.analyzer import analyze_file
from q_safe.scanner import scan

st.set_page_config(page_title="Q-SAFE Defender", page_icon="🛡️", layout="wide")
st.title("Q-SAFE Defender")
st.caption("Local static file triage — no files are executed and no automatic remediation occurs.")

with st.sidebar:
    st.subheader("Scan scope")
    root = st.text_input("Directory or file", value=str(Path.home() / "Downloads"))
    limit = st.number_input("Maximum files", min_value=1, max_value=100000, value=5000, step=500)
    run = st.button("Start scan", type="primary")
    st.warning("Scan user-owned folders first. Do not run this dashboard as root.")

if "results" not in st.session_state:
    st.session_state.results = []

if run:
    with st.spinner("Inspecting files as inert data..."):
        st.session_state.results = scan([root], output="reports/dashboard-scan.jsonl", max_files=int(limit))

results = st.session_state.results
if not results:
    st.info("No scan results yet. Select a scope and start a scan.")
else:
    frame = pd.DataFrame([{
        "Verdict": x["verdict"], "Score": x["score"], "Type": x["file_type"],
        "Size": x["size"], "Path": x["path"], "SHA-256": x["sha256"]
    } for x in results])
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Files inspected", len(frame))
    c2.metric("High risk", int((frame["Verdict"]=="HIGH_RISK").sum()))
    c3.metric("Suspicious", int((frame["Verdict"]=="SUSPICIOUS").sum()))
    c4.metric("Review", int((frame["Verdict"]=="REVIEW").sum()))
    st.subheader("Findings")
    st.dataframe(frame, use_container_width=True, hide_index=True)
    selected = st.selectbox("Inspect evidence", options=frame["Path"].tolist())
    detail = next(x for x in results if x["path"] == selected)
    st.json(detail)
    st.caption("A low score means no configured static indicators matched; it does not prove the file is benign.")
