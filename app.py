"""SkillBouncer — Streamlit frontend for the Auditor.

Run with: streamlit run app.py
"""
from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

import streamlit as st

from auditor import scan_path

st.set_page_config(page_title="SkillBouncer", layout="wide")

st.title("SkillBouncer")
st.caption("The AI-powered bouncer for third-party AI agent skills.")

st.markdown(
    "Upload a skill — a `.zip` archive or a single source file — to scan it for "
    "leaked secrets and risky patterns before you let an agent run it."
)

uploaded = st.file_uploader(
    "Skill file",
    type=["zip", "py", "js", "ts", "yaml", "yml", "json", "md", "txt"],
)

if uploaded is None:
    st.info("Awaiting a skill upload.")
    st.stop()

with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)

    if uploaded.name.lower().endswith(".zip"):
        archive_path = tmp_path / uploaded.name
        archive_path.write_bytes(uploaded.getvalue())
        extract_root = tmp_path / "extracted"
        extract_root.mkdir()
        try:
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(extract_root)
        except zipfile.BadZipFile:
            st.error("Could not read the archive — is it a valid .zip?")
            st.stop()
        scan_target = extract_root
    else:
        scan_target = tmp_path / uploaded.name
        scan_target.write_bytes(uploaded.getvalue())

    result = scan_path(scan_target)
    prefix = str(tmp_path) + "/"

label_color = {"clean": "green", "low": "blue", "medium": "orange", "high": "red"}[result.risk_label]

col1, col2, col3 = st.columns(3)
col1.metric("Risk score", f"{result.risk_score} / 100")
col2.metric("Files scanned", result.files_scanned)
col3.markdown(f"**Verdict**\n\n:{label_color}[{result.risk_label.upper()}]")

if result.findings:
    st.subheader(f"Findings ({len(result.findings)})")
    st.dataframe(
        [
            {
                "File": f.file.replace(prefix, "", 1),
                "Line": f.line,
                "Rule": f.rule,
                "Snippet": f.snippet,
            }
            for f in result.findings
        ],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.success("No secret-shaped patterns detected.")
