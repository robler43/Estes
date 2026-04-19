"""Color and severity tokens for the Estes dashboard.

This module is the single source of truth for the dashboard's visual system
(per `handoff/ui_design.md` §2.1 and §9). The same hex values appear in
`assets/styles.css` as CSS variables — any change here must be mirrored there
(or generated; see `theme_css_variables()`).
"""
from __future__ import annotations

# Palette --------------------------------------------------------------------

BG_0 = "#0a0e14"        # page background
BG_1 = "#111821"        # cards / panels
BG_2 = "#1a232f"        # elevated surfaces (hover, expanded card)
BORDER = "#1f2a37"
TEXT_0 = "#e6edf3"      # primary
TEXT_1 = "#9aa7b4"      # secondary
TEXT_2 = "#5a6573"      # tertiary / metadata

ACCENT = "#22ff88"          # neon green — brand, primary CTA, "Safe"
ACCENT_DIM = "#22ff8833"    # accent at ~20% alpha (drag-over glow, fix bar)
ACCENT_BRIGHT = "#4cffa1"   # primary CTA hover
WARN = "#ffb454"            # "Warning" severity
DANGER = "#ff4d6d"          # "High Risk" severity, destructive CTA
INFO = "#5fb5ff"            # informational badges, LLM source tag


# Severity → display style ----------------------------------------------------

# `auditor.OverallSeverity` is the Phase 1 vocabulary. We deliberately map
# `"High Risk"` to "DANGER" for the badge text so the dashboard reads as a
# security console while the underlying scan vocabulary stays stable.
SEVERITY_STYLE: dict[str, dict[str, str]] = {
    "Safe": {
        "color": ACCENT,
        "label": "SAFE",
        "dot": ACCENT,
    },
    "Warning": {
        "color": WARN,
        "label": "WARNING",
        "dot": WARN,
    },
    "High Risk": {
        "color": DANGER,
        "label": "HIGH RISK",
        "dot": DANGER,
    },
}

# Per-finding severity (Phase 1 `Finding.severity` ∈ {info, warning, high})
FINDING_SEVERITY_STYLE: dict[str, dict[str, str]] = {
    "high": {"color": DANGER, "label": "HIGH"},
    "warning": {"color": WARN, "label": "WARNING"},
    "info": {"color": INFO, "label": "INFO"},
}

# Finding source ∈ {static, ast, llm}
# Each entry now carries a label + icon + plain-English description so the
# dashboard can surface *which pass* caught a finding (the user has been
# asking "was this a regex hit, taint analysis, or the LLM?" — give them
# a one-glance answer).
SOURCE_STYLE: dict[str, dict[str, str]] = {
    "static": {
        "color":  WARN,
        "label":  "STATIC",
        "icon":   "▦",
        "desc":   "Regex / entropy pattern match",
    },
    "ast": {
        "color":  INFO,
        "label":  "AST",
        "icon":   "⌬",
        "desc":   "Python AST taint analysis",
    },
    "llm": {
        "color":  ACCENT,
        "label":  "LLM",
        "icon":   "✨",
        "desc":   "Deep-semantic LLM review",
    },
}


def theme_css_variables() -> str:
    """Emit a CSS `:root { --foo: ... }` block matching this module.

    Loaded once at app startup so `assets/styles.css` can reference tokens
    by name and stay free of hard-coded hex values.
    """
    pairs = [
        ("--bg-0", BG_0),
        ("--bg-1", BG_1),
        ("--bg-2", BG_2),
        ("--border", BORDER),
        ("--text-0", TEXT_0),
        ("--text-1", TEXT_1),
        ("--text-2", TEXT_2),
        ("--accent", ACCENT),
        ("--accent-dim", ACCENT_DIM),
        ("--accent-bright", ACCENT_BRIGHT),
        ("--warn", WARN),
        ("--danger", DANGER),
        ("--info", INFO),
    ]
    body = "\n".join(f"  {k}: {v};" for k, v in pairs)
    return f":root {{\n{body}\n}}"


__all__ = [
    "ACCENT",
    "ACCENT_BRIGHT",
    "ACCENT_DIM",
    "BG_0",
    "BG_1",
    "BG_2",
    "BORDER",
    "DANGER",
    "FINDING_SEVERITY_STYLE",
    "INFO",
    "SEVERITY_STYLE",
    "SOURCE_STYLE",
    "TEXT_0",
    "TEXT_1",
    "TEXT_2",
    "WARN",
    "theme_css_variables",
]
