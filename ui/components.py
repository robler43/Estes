"""Pure-render helpers for the Estes dashboard.

Every helper that interpolates dynamic strings into HTML routes them through
`html.escape()` — finding messages, snippets, and file paths can originate
from a malicious skill (or an LLM coerced by one), so all variable content
is treated as untrusted. See handoff/ui_design.md §9.
"""
from __future__ import annotations

import html
from pathlib import Path

import streamlit as st

from auditor import Finding, ScanReport
from ui import explainers, theme

# Inlined logo: kept here so app.py has no static-file-serving dependency.
# Source of truth: assets/logo.svg.
LOGO_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40" fill="none"
     stroke="currentColor" stroke-width="2" stroke-linecap="round"
     stroke-linejoin="round" class="es-header__logo">
  <path d="M20 4 L33 8 V19 C33 26.5 27.5 32.5 20 35 C12.5 32.5 7 26.5 7 19 V8 Z" />
  <path d="M14 18 H26" />
  <path d="M14 23 H22" />
  <path d="M28 27 L31 32 L25 30 Z" fill="currentColor" stroke="none" opacity="0.85" />
</svg>"""

REPO_URL = "https://github.com/RobinHo-coder/Estes"


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------


def inject_styles() -> None:
    """Inject CSS variables (from `ui.theme`) followed by `assets/styles.css`."""
    css_path = Path(__file__).resolve().parent.parent / "assets" / "styles.css"
    css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""
    st.markdown(
        f"<style>{theme.theme_css_variables()}\n{css}</style>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


def render_header() -> None:
    st.markdown(
        f"""
<div class="es-header">
  <div class="es-header__brand">
    {LOGO_SVG}
    <div class="es-header__wordmark">
      <div class="es-header__name">Estes</div>
      <div class="es-header__tagline">Keep secrets out of your agent chats</div>
    </div>
  </div>
  <nav class="es-header__nav">
    <a href="#" target="_self">Docs</a>
    <a href="{html.escape(REPO_URL)}" target="_blank" rel="noopener">GitHub</a>
  </nav>
</div>
""",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------------


def render_empty_state() -> None:
    """The 'what we look for' triptych shown before any scan runs."""
    st.markdown('<div class="es-section-title"><h3>What we look for</h3></div>',
                unsafe_allow_html=True)
    cards = [
        ("env-var leaks",
         "<code>print()</code> or logging of <code>os.environ</code> values that "
         "agent frameworks pipe into LLM context."),
        ("semantic mismatches",
         "Manifest claims X, code does Y. Detected by an LLM pass against the "
         "<code>SKILL.md</code> description."),
        ("secret file reads",
         "Reads of <code>.env</code>, <code>~/.ssh/id_*</code>, AWS credentials, "
         "<code>.pem</code> / <code>.key</code> files."),
    ]
    cols = st.columns(3)
    for col, (title, body) in zip(cols, cards):
        with col:
            st.markdown(
                f"""
<div class="es-feature-card">
  <div class="es-feature-card__icon">◆</div>
  <div class="es-feature-card__title">{html.escape(title)}</div>
  <div class="es-feature-card__body">{body}</div>
</div>
""",
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# Results — score + badge + meta
# ---------------------------------------------------------------------------


def _badge_html(severity: str) -> str:
    style = theme.SEVERITY_STYLE.get(severity, theme.SEVERITY_STYLE["Warning"])
    color = style["color"]
    label = style["label"]
    return (
        f'<span class="es-badge" '
        f'style="color:{color};background:{color}1f;border-color:{color}55">'
        f'<span class="es-badge__dot" style="background:{color}"></span>'
        f'{html.escape(label)}'
        f"</span>"
    )


def render_score_panel(report: ScanReport) -> None:
    style = theme.SEVERITY_STYLE.get(report.severity,
                                     theme.SEVERITY_STYLE["Warning"])
    score_color = style["color"]

    llm_meta = "llm: off"
    llm_color = theme.TEXT_2
    if report.llm_used:
        llm_meta = "llm: ✓"
        llm_color = theme.ACCENT
    elif any("LLM check skipped" in w for w in report.warnings):
        llm_meta = "llm: skipped"
        llm_color = theme.WARN

    duration = report.duration_ms / 1000.0
    files_word = "file" if report.files_scanned == 1 else "files"
    findings_word = "finding" if len(report.findings) == 1 else "findings"

    col_score, col_badge, col_meta = st.columns([1, 1, 2], gap="medium")
    with col_score:
        st.markdown(
            f"""
<div class="es-score">
  <div class="es-score__num" style="color:{score_color}">{report.risk_score}</div>
  <div class="es-score__denom">/ 100 risk score</div>
</div>
""",
            unsafe_allow_html=True,
        )
    with col_badge:
        st.markdown(
            f'<div style="display:flex;align-items:center;height:100%">{_badge_html(report.severity)}</div>',
            unsafe_allow_html=True,
        )
    with col_meta:
        st.markdown(
            f"""
<div style="display:flex;align-items:center;height:100%">
  <div class="es-meta">
    <span>{len(report.findings)} {findings_word}</span>
    <span class="es-meta__sep">·</span>
    <span>{report.files_scanned} {files_word} scanned</span>
    <span class="es-meta__sep">·</span>
    <span>{duration:.1f} s</span>
    <span class="es-meta__sep">·</span>
    <span style="color:{llm_color}">{html.escape(llm_meta)}</span>
  </div>
</div>
""",
            unsafe_allow_html=True,
        )


def render_fix_banner(report: ScanReport) -> None:
    style = theme.SEVERITY_STYLE.get(report.severity,
                                     theme.SEVERITY_STYLE["Warning"])
    color = style["color"]
    text = report.suggested_fix or "No suggested fix."
    st.markdown(
        f"""
<div class="es-fix-banner" style="border-left-color:{color}">
  <span class="es-fix-banner__label">Recommended</span>
  <span>{html.escape(text)}</span>
</div>
""",
        unsafe_allow_html=True,
    )


def render_warnings(report: ScanReport) -> None:
    if not report.warnings:
        return
    items = "".join(f"<li>{html.escape(w)}</li>" for w in report.warnings)
    with st.expander(f"{len(report.warnings)} scan warning(s)", expanded=False):
        st.markdown(
            f'<div class="es-warnings"><ul>{items}</ul></div>',
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


_SEV_RANK = {"high": 0, "warning": 1, "info": 2}


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (_SEV_RANK.get(f.severity, 9), f.file, f.line),
    )


def _severity_glyph(sev: str) -> str:
    return {"high": "▲", "warning": "△", "info": "·"}.get(sev, "·")


def _finding_label_text(f: Finding) -> str:
    """Plain-text expander label.

    Streamlit 1.39 does not reliably support full HTML in expander labels,
    so we encode the analysis source as the leading token (where the eye
    lands first) followed by the severity glyph + label. Per ui_design.md
    §9 fallback note.
    """
    sev_label = theme.FINDING_SEVERITY_STYLE.get(
        f.severity, theme.FINDING_SEVERITY_STYLE["info"]
    )["label"]
    src_label = theme.SOURCE_STYLE.get(
        f.source, theme.SOURCE_STYLE["static"]
    )["label"]
    glyph = _severity_glyph(f.severity)
    loc = f"{f.file}:{f.line}" if f.file else "(top-level)"
    # Layout:  [STATIC]  ▲ HIGH    ES-PRINT-CRED-01      weather.py:12
    return (
        f"[{src_label:<6}]  {glyph} {sev_label:<7}  "
        f"{f.id:<24}  {loc}"
    )


def render_finding_card(f: Finding) -> None:
    """Render a single finding as a "What was wrong → Why it matters →
    What to change" expander.

    Each section is clearly labeled so the audience (a developer triaging a
    third-party skill) can answer two questions in under five seconds:

      • What did this skill do that I should worry about?
      • What should it look like instead?
    """
    sev_style = theme.FINDING_SEVERITY_STYLE.get(
        f.severity, theme.FINDING_SEVERITY_STYLE["info"]
    )
    src_style = theme.SOURCE_STYLE.get(f.source, theme.SOURCE_STYLE["static"])
    explainer = explainers.explain(f.category, f.id)
    friendly_msg = explainers.humanize_message(f.id, f.message)

    label = _finding_label_text(f)
    with st.expander(label, expanded=False):
        # ---- Header strip: source pill + severity + rule id + location ----
        st.markdown(
            f"""
<div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-bottom:14px">
  <span class="es-src-pill" style="color:{src_style['color']}">
    <span class="es-src-pill__icon">{html.escape(src_style.get('icon', '·'))}</span>
    {html.escape(src_style['label'])}
    <span class="es-src-pill__desc">{html.escape(src_style.get('desc', ''))}</span>
  </span>
  <span style="color:{sev_style['color']};font-weight:600;font-size:12px;letter-spacing:0.8px">
    {html.escape(sev_style['label'])}
  </span>
  <span style="font-family:'JetBrains Mono',monospace;font-size:13px;color:{theme.TEXT_0}">
    {html.escape(f.id)}
  </span>
  <span style="color:{theme.TEXT_1};font-size:13px;font-family:'JetBrains Mono',monospace">
    {html.escape(f.file)}{':' + str(f.line) if f.line else ''}
  </span>
</div>
""",
            unsafe_allow_html=True,
        )

        # ---- Section 1: What was wrong (message + BEFORE snippet) --------
        before_block = ""
        if f.snippet:
            before_block = (
                f'<div class="es-diff-cap">{html.escape(explainer.before_caption)}</div>'
                f'<pre class="es-diff es-diff--before">'
                f'<span class="es-diff__sigil">−</span>'
                f'<span>{html.escape(f.snippet)}</span>'
                f'</pre>'
            )
        st.markdown(
            f"""
<div class="es-section">
  <div class="es-section__head es-section__head--bad">
    <span class="es-section__icon">✕</span>
    <span class="es-section__label">What was wrong</span>
  </div>
  <div class="es-section__body">
    <div style="font-size:14px;color:{theme.TEXT_0};line-height:1.55;margin-bottom:8px">
      {html.escape(friendly_msg)}
    </div>
    {before_block}
  </div>
</div>
""",
            unsafe_allow_html=True,
        )

        # ---- Section 2: Why it matters (category-aware risk explanation) -
        st.markdown(
            f"""
<div class="es-section">
  <div class="es-section__head es-section__head--why">
    <span class="es-section__icon">⚠</span>
    <span class="es-section__label">Why it matters</span>
  </div>
  <div class="es-section__body">
    <div style="font-size:13.5px;color:{theme.TEXT_1};line-height:1.6">
      {html.escape(explainer.why)}
    </div>
  </div>
</div>
""",
            unsafe_allow_html=True,
        )

        # ---- Section 3: What to change (fix prose + AFTER template) ------
        fix_prose = (f.suggested_fix or "").strip()
        after_block = ""
        if explainer.after_template:
            after_block = (
                '<div class="es-diff-cap">Recommended pattern (template):</div>'
                f'<pre class="es-diff es-diff--after">'
                f'<span class="es-diff__sigil">+</span>'
                f'<span>{html.escape(explainer.after_template)}</span>'
                f'</pre>'
            )
        if fix_prose or after_block:
            st.markdown(
                f"""
<div class="es-section">
  <div class="es-section__head es-section__head--good">
    <span class="es-section__icon">✓</span>
    <span class="es-section__label">What to change</span>
  </div>
  <div class="es-section__body">
    {f'<div style="font-size:13.5px;color:{theme.TEXT_0};line-height:1.6;margin-bottom:8px">{html.escape(fix_prose)}</div>' if fix_prose else ''}
    {after_block}
  </div>
</div>
""",
                unsafe_allow_html=True,
            )


def render_source_summary(report: ScanReport) -> None:
    """Strip above the findings list — counts of how each pass contributed.

    Renders three pills (STATIC / AST / LLM) with the number of findings each
    pass produced. Empty passes are dimmed so the user can tell at a glance
    whether the LLM pass actually ran. Hides itself when there are no
    findings (the empty-state hero card already conveys "all clear").
    """
    if not report.findings:
        return
    counts: dict[str, int] = {"static": 0, "ast": 0, "llm": 0}
    for f in report.findings:
        counts[f.source] = counts.get(f.source, 0) + 1

    chips = []
    for src in ("static", "ast", "llm"):
        style = theme.SOURCE_STYLE[src]
        n = counts.get(src, 0)
        chips.append(
            f'<span class="es-src-summary__chip" data-empty="{str(n == 0).lower()}" '
            f'style="color:{style["color"]}">'
            f'<span>{html.escape(style.get("icon", "·"))}</span>'
            f'{html.escape(style["label"])}'
            f'<span class="num">{n}</span>'
            f'</span>'
        )
    st.markdown(
        f'<div class="es-src-summary">'
        f'<span class="es-src-summary__lab">Found by</span>'
        f'{"".join(chips)}'
        f'</div>',
        unsafe_allow_html=True,
    )


_RENDER_CAP = 50


def render_findings_list(report: ScanReport,
                         severity_filter: str,
                         source_filter: str) -> None:
    findings = report.findings
    if severity_filter != "All":
        findings = [f for f in findings if f.severity == severity_filter.lower()]
    if source_filter != "All":
        findings = [f for f in findings if f.source == source_filter]

    findings = _sort_findings(findings)

    if not findings:
        if not report.findings:
            # No findings at all: hero card.
            st.markdown(
                f"""
<div class="es-card" style="border-color:{theme.ACCENT};margin-top:12px">
  <div style="font-size:18px;font-weight:600;color:{theme.ACCENT}">✓ No issues found</div>
  <div style="font-size:13px;color:{theme.TEXT_1};margin-top:6px">
    This skill is clean against the current ruleset. Static analysis is not
    proof of safety — review manually before granting credentials.
  </div>
</div>
""",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f'<div style="color:{theme.TEXT_1};margin:12px 0">'
                f'No findings match the current filters.</div>',
                unsafe_allow_html=True,
            )
        return

    visible = findings[:_RENDER_CAP]
    for f in visible:
        render_finding_card(f)

    if len(findings) > _RENDER_CAP:
        remaining = len(findings) - _RENDER_CAP
        st.markdown(
            f'<div style="color:{theme.TEXT_2};font-size:13px;margin-top:8px">'
            f'+ {remaining} more findings — adjust filters to drill down.'
            f"</div>",
            unsafe_allow_html=True,
        )


__all__ = [
    "REPO_URL",
    "inject_styles",
    "render_empty_state",
    "render_finding_card",
    "render_findings_list",
    "render_fix_banner",
    "render_header",
    "render_score_panel",
    "render_source_summary",
    "render_warnings",
]
