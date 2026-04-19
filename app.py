"""Estes dashboard — Streamlit frontend for the Auditor.

Run with: streamlit run app.py

Implements the design in handoff/ui_design.md (Step 2). Pure layout + state
plumbing — every render call is in `ui/components.py`, every color token in
`ui/theme.py`, and every scan call goes through `auditor.scan_skill`.
"""
from __future__ import annotations

import io
import shutil
import tempfile
import zipfile
from pathlib import Path

import streamlit as st

from auditor import Finding, ScanReport, scan_skill
from ui import components

# ---------------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Estes",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

components.inject_styles()
components.render_header()


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

st.session_state.setdefault("report", None)
st.session_state.setdefault("scan_root_dir", None)
st.session_state.setdefault("severity_filter", "All")
st.session_state.setdefault("source_filter", "All")


def _reset_report() -> None:
    """Drop any existing report when the user changes the source."""
    st.session_state["report"] = None
    prev = st.session_state.get("scan_root_dir")
    if prev and Path(prev).exists():
        shutil.rmtree(prev, ignore_errors=True)
    st.session_state["scan_root_dir"] = None


# ---------------------------------------------------------------------------
# Upload area
# ---------------------------------------------------------------------------

upload_col, _ = st.columns([1, 0.001])  # full-width via a single col w/ side spacer
with upload_col:
    uploaded = st.file_uploader(
        "Drop a third-party skill (.zip or single source file)",
        type=["zip", "py", "js", "ts", "yaml", "yml", "json", "md", "txt"],
        label_visibility="collapsed",
        on_change=_reset_report,
    )

    st.markdown('<div class="es-upload-or">or paste a public GitHub link</div>',
                unsafe_allow_html=True)

    github_url = st.text_input(
        "GitHub URL",
        value="",
        placeholder="https://github.com/owner/repo  or  /tree/branch/subpath",
        label_visibility="collapsed",
        on_change=_reset_report,
    ).strip()

if uploaded is not None and github_url:
    st.markdown(
        f'<div style="color:{components.theme.TEXT_2};font-size:12px;margin-top:-4px">'
        f"Both upload and URL provided — using the URL."
        f"</div>",
        unsafe_allow_html=True,
    )

source_ready = bool(github_url) or (uploaded is not None)


# ---------------------------------------------------------------------------
# Action bar
# ---------------------------------------------------------------------------


def _materialize_upload() -> Path | None:
    """Persist a Streamlit upload to a temp dir we manage; return its path.

    The dir is tracked in session_state so the next scan can clean it up.
    """
    if uploaded is None:
        return None
    tmp_dir = Path(tempfile.mkdtemp(prefix="estes_ui_"))
    st.session_state["scan_root_dir"] = str(tmp_dir)

    if uploaded.name.lower().endswith(".zip"):
        archive = tmp_dir / uploaded.name
        archive.write_bytes(uploaded.getvalue())
        return archive
    target = tmp_dir / uploaded.name
    target.write_bytes(uploaded.getvalue())
    return target


def _run_scan() -> None:
    source: str | Path | None
    if github_url:
        source = github_url
    else:
        source = _materialize_upload()
    if source is None:
        st.error("No source provided.")
        return

    try:
        with st.spinner("Scanning skill — running static, AST, and LLM passes…"):
            report = scan_skill(source, llm=True)
    except Exception as exc:  # noqa: BLE001
        st.error(f"Scan failed: {exc.__class__.__name__}: {exc}")
        return

    st.session_state["report"] = report


report: ScanReport | None = st.session_state.get("report")
has_report = report is not None
non_safe = has_report and report.severity != "Safe"  # type: ignore[union-attr]
zip_or_dir_source = (
    bool(github_url)
    or (uploaded is not None and uploaded.name.lower().endswith(".zip"))
)

st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)

bar = st.columns([1.2, 1.2, 1.2, 4])
with bar[0]:
    st.markdown('<div class="es-primary">', unsafe_allow_html=True)
    if st.button("Scan Skill", disabled=not source_ready, use_container_width=True):
        _run_scan()
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)
with bar[1]:
    if st.button(
        "Apply Wrapper",
        disabled=not non_safe,
        use_container_width=True,
        help=("Run the Estes Wrapper as a local proxy."
              if non_safe else
              "Wrapper is only useful when findings exist."),
    ):
        st.session_state["show_wrapper"] = True
with bar[2]:
    download_disabled = not (non_safe and zip_or_dir_source)
    download_help = (
        "Generates a stub-patched copy with `# estes: ignore` markers."
        if not download_disabled else
        "Available for .zip uploads or GitHub sources with at least one finding."
    )
    if download_disabled:
        st.button(
            "Download Fixed",
            disabled=True,
            use_container_width=True,
            help=download_help,
        )


# ---------------------------------------------------------------------------
# Apply Wrapper modal-equivalent
# ---------------------------------------------------------------------------

if st.session_state.get("show_wrapper"):
    with st.expander("Apply Wrapper — local proxy install", expanded=True):
        st.markdown(
            """
The runtime Wrapper redacts skill output before it reaches the LLM context.
Start it locally; point your agent's tool-output URL at `localhost:8000`.

```bash
pip install -r requirements.txt
uvicorn wrapper:app --host 127.0.0.1 --port 8000
```

The Wrapper exposes `POST /redact` (real-time redaction) and `POST /scan`
(one-shot static scan against the same ruleset shown above).

> **Note:** Phase 1 ships the Wrapper as a manual proxy. Native Antigravity
> integration is on the Phase 2 roadmap (KG-3).
"""
        )
        if st.button("Close", key="close_wrapper"):
            st.session_state["show_wrapper"] = False
            st.rerun()


# ---------------------------------------------------------------------------
# Download Fixed Skill (stub auto-patch)
# ---------------------------------------------------------------------------


def _build_fixed_zip(report: ScanReport) -> bytes:
    """Stub auto-patch: produce a zip mirroring the scanned root with
    `# estes: ignore` (or `// estes: ignore`) markers appended
    on every flagged line. Reads from disk via the report's recorded paths
    where possible; falls back to the in-memory upload bytes."""
    findings_by_file: dict[str, set[int]] = {}
    for f in report.findings:
        if f.file and f.line:
            findings_by_file.setdefault(f.file, set()).add(f.line)

    def _comment_for(path: str) -> str:
        suffix = Path(path).suffix.lower()
        if suffix in {".py", ".sh", ".rb", ".yaml", ".yml", ".toml", ".env",
                      ".ini"}:
            return "  # estes: ignore"
        if suffix in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".go",
                      ".java", ".c", ".cpp", ".h"}:
            return "  // estes: ignore"
        return "  # estes: ignore"

    # Resolve actual on-disk root: scan_skill records skill_root relative to
    # its temp workspace. For the UI we re-read from the materialized upload
    # dir; for GitHub sources the temp workspace is gone, so we ship a
    # findings-only patch sheet instead.
    materialized = st.session_state.get("scan_root_dir")
    buf = io.BytesIO()

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if materialized and Path(materialized).exists():
            root = Path(materialized)
            # If a single .zip was uploaded, extract it on the fly.
            zips = list(root.glob("*.zip"))
            if zips:
                src_root = root / "_extracted"
                src_root.mkdir(exist_ok=True)
                with zipfile.ZipFile(zips[0]) as src_zf:
                    src_zf.extractall(src_root)
            else:
                src_root = root

            for path in src_root.rglob("*"):
                if not path.is_file():
                    continue
                rel = path.relative_to(src_root).as_posix()
                try:
                    text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    zf.write(path, arcname=rel)
                    continue
                lines = text.splitlines(keepends=True)
                hot = findings_by_file.get(rel, set())
                if hot:
                    for ln in hot:
                        idx = ln - 1
                        if 0 <= idx < len(lines):
                            line = lines[idx].rstrip("\n")
                            if "estes: ignore" not in line:
                                lines[idx] = line + _comment_for(rel) + "\n"
                zf.writestr(rel, "".join(lines))

        # Always include a patch sheet so users have a manifest of changes.
        sheet = "# Estes stub auto-patch\n\n"
        sheet += f"Source: {report.source}\n"
        sheet += f"Severity: {report.severity}  Score: {report.risk_score}\n\n"
        sheet += "## Lines marked with `estes: ignore`\n\n"
        for file, lines in sorted(findings_by_file.items()):
            sheet += f"- {file}: {sorted(lines)}\n"
        sheet += (
            "\n> **Stub patch — review before redistributing.** This silences "
            "findings, it does not fix the underlying leak.\n"
        )
        zf.writestr("ESTES_PATCH.md", sheet)

    return buf.getvalue()


with bar[2]:
    if not download_disabled and report is not None:
        try:
            data = _build_fixed_zip(report)
            st.download_button(
                "Download Fixed",
                data=data,
                file_name="skill_fixed.zip",
                mime="application/zip",
                use_container_width=True,
                help="Stub patch — review before redistributing.",
            )
        except Exception as exc:  # noqa: BLE001
            st.error(f"Could not build patch zip: {exc}")


# ---------------------------------------------------------------------------
# Results panel OR empty state
# ---------------------------------------------------------------------------

st.markdown('<div style="height:24px"></div>', unsafe_allow_html=True)

if report is None:
    components.render_empty_state()
    st.stop()

components.render_score_panel(report)
st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)
components.render_fix_banner(report)
components.render_warnings(report)

# Findings header + filters
st.markdown('<div style="height:18px"></div>', unsafe_allow_html=True)
title_col, sev_col, src_col = st.columns([3, 1, 1], gap="small")
with title_col:
    st.markdown(
        f"""
<div class="es-section-title">
  <h3>Findings <span class="es-section-title__count">({len(report.findings)})</span></h3>
</div>
""",
        unsafe_allow_html=True,
    )
with sev_col:
    st.session_state["severity_filter"] = st.selectbox(
        "Severity",
        options=["All", "High", "Warning", "Info"],
        index=["All", "High", "Warning", "Info"].index(
            st.session_state["severity_filter"]
        ),
        label_visibility="collapsed",
    )
with src_col:
    st.session_state["source_filter"] = st.selectbox(
        "Source",
        options=["All", "static", "ast", "llm"],
        index=["All", "static", "ast", "llm"].index(
            st.session_state["source_filter"]
        ),
        label_visibility="collapsed",
    )

components.render_findings_list(
    report,
    severity_filter=st.session_state["severity_filter"],
    source_filter=st.session_state["source_filter"],
)
