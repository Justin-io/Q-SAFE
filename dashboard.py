"""Optional Streamlit UI. Install Streamlit separately to use this module."""
from pathlib import Path
import streamlit as st
from qsafe import STORE, quarantine_file, scan_target

st.set_page_config(page_title="Q-SAFE | Defensive Console", page_icon="🛡️", layout="wide")
st.title("Q-SAFE")
st.caption("Local-first static malware triage · Read-only scan · Explicit quarantine")
target = st.text_input("File or directory to scan", value=".")
if st.button("Run scan", type="primary"):
    location = Path(target).expanduser()
    if not location.exists():
        st.error("Selected path does not exist.")
    else:
        with st.spinner("Inspecting files without executing them..."):
            st.session_state["report"] = scan_target(location)

report = st.session_state.get("report")
if report:
    summary = report["summary"]
    cols = st.columns(4)
    for col, label, key in zip(cols, ["Files scanned", "Flagged", "High risk", "Suspicious"], ["scanned", "flagged", "high_risk", "suspicious"]):
        col.metric(label, summary[key])
    st.caption(f"Target: {report['target']} · Scan time: {report['scanned_at']}")
    rows = []
    for item in sorted(report["files"], key=lambda row: row["analysis"]["score"], reverse=True):
        analysis = item["analysis"]
        rows.append({"Verdict": analysis["verdict"], "Score": analysis["score"], "Polymorphic candidate": analysis["polymorphic_candidate"], "Format": analysis["format"], "Entropy": analysis["entropy"], "File": item["path"]})
    st.dataframe(rows, use_container_width=True, hide_index=True)
    candidates = [item for item in report["files"] if item["analysis"]["score"] >= 20]
    if candidates:
        st.subheader("Triage details")
        selected = st.selectbox("Select flagged file", [item["path"] for item in candidates])
        chosen = next(item for item in candidates if item["path"] == selected)
        for finding in chosen["analysis"]["evidence"]:
            st.write(f"+{finding['points']} · {finding['reason']}")
        st.warning("A heuristic score is not proof of malware. Validate before taking action.")
        confirm = st.checkbox("I reviewed the findings and confirm quarantine.")
        if st.button("Quarantine selected file", disabled=not confirm):
            try:
                record = quarantine_file(Path(selected), STORE, confirmed=True)
                st.success(f"Quarantined and SHA-256 verified. ID: {record['id']}")
            except Exception as exc:
                st.error(f"Quarantine failed: {exc}")
else:
    st.info("Run a scan to populate this console. No files are scanned until you click Run scan.")
st.divider()
st.caption("Q-SAFE does not execute inspected files. Compression and encryption can also cause high entropy.")
