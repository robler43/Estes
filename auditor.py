"""Estes Auditor — layered scanner for third-party agent skills.

Implements `scan_skill(source, *, llm=True)` per handoff/auditor_design.md.

Three passes share one ruleset:

    Pass A  static    — regex (Phase 0 patterns) + Shannon entropy
    Pass B  ast       — Python AST visitor for env-var leaks, eval/exec, etc.
    Pass C  llm       — semantic "does the code match the manifest?" check
                        (Anthropic Claude Haiku or xAI Grok, both optional)

The module is import-safe with no API keys configured: the LLM pass degrades
to a single warning string and the rest of the report is unaffected.

Backwards compatible: `SECRET_PATTERNS`, `scan_text`, `scan_path`, and
`redact_text` from the Phase 0 module are preserved so wrapper.py and app.py
keep working without changes.
"""
from __future__ import annotations

import ast
import json
import logging
import math
import os
import re
import shutil
import tempfile
import time
import zipfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import requests

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    # dotenv is optional at runtime — env vars work fine without it.
    pass

log = logging.getLogger("estes.auditor")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCANNABLE_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".sh", ".rb", ".go",
    ".yaml", ".yml", ".json", ".env", ".toml", ".ini",
    ".md", ".txt",
}

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build",
    "__pycache__", ".venv", "venv", ".tox", ".pytest_cache",
}

MANIFEST_NAMES = (
    "SKILL.md", "SKILL.yaml", "SKILL.yml", "SKILL.json",
    "manifest.yaml", "manifest.yml", "manifest.json",
)

DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_PER_FILE_BYTES = 500 * 1024
DEFAULT_TIMEOUT_S = 30.0

IGNORE_DIRECTIVE_RE = re.compile(r"(?:#|//)\s*estes\s*:\s*ignore", re.IGNORECASE)

# Hosts the AST pass treats as "phone-home suspicious" when paired with env-var access.
NETWORK_ALLOWLIST = {
    "localhost", "127.0.0.1", "0.0.0.0",
}

SECRET_FILE_GLOBS = (
    re.compile(r"(?i)(^|/)\.aws/credentials$"),
    re.compile(r"(?i)(^|/)\.ssh/id_[a-z0-9_]+$"),
    re.compile(r"(?i)\.pem$"),
    re.compile(r"(?i)\.key$"),
    re.compile(r"(?i)(^|/)\.env(\.[a-z0-9_-]+)?$"),
)


# ---------------------------------------------------------------------------
# Pass A regex ruleset (preserved from Phase 0; same source-of-truth for
# wrapper.py /redact). Each rule has a stable id used in Finding.id.
# ---------------------------------------------------------------------------

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "Generic API key assignment": re.compile(
        r"""(?ix)
        \b(api[_-]?key|secret|token|passwd|password)\b
        \s*[:=]\s*
        ['"][A-Za-z0-9_\-\.]{12,}['"]
        """
    ),
    "Bearer token": re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}"),
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Private key block": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    "Debug print of credential": re.compile(
        r"(?i)\bprint\s*\(.*?(api[_-]?key|token|password|secret|bearer).*?\)"
    ),
    "Logging of credential": re.compile(
        r"(?i)\b(log|logger)\.(debug|info|warning|error)\s*\(.*?(api[_-]?key|token|password|secret).*?\)"
    ),
}

_STATIC_RULE_META: dict[str, tuple[str, str, str, str]] = {
    # rule name -> (id, severity, category, suggested_fix)
    "Generic API key assignment": (
        "ES-CRED-ASSIGN-01", "warning", "credential_leak",
        "Move the literal into an environment variable or secret store.",
    ),
    "Bearer token": (
        "ES-BEARER-01", "high", "credential_leak",
        "Never embed bearer tokens in source. Load them from env at call time.",
    ),
    "AWS access key id": (
        "ES-AWS-KEY-01", "high", "credential_leak",
        "Rotate the key immediately and load credentials from the AWS SDK chain.",
    ),
    "Private key block": (
        "ES-PRIVKEY-01", "high", "credential_leak",
        "Remove the embedded private key; use a key management system.",
    ),
    "Debug print of credential": (
        "ES-PRINT-CRED-01", "high", "credential_leak",
        "Remove the print() or redact the credential before printing.",
    ),
    "Logging of credential": (
        "ES-LOG-CRED-01", "high", "credential_leak",
        "Strip the credential from the log call or lower the log level to nothing.",
    ),
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

Severity = Literal["info", "warning", "high"]
OverallSeverity = Literal["Safe", "Warning", "High Risk"]
FindingSource = Literal["static", "ast", "llm"]


@dataclass(slots=True)
class Finding:
    id: str
    severity: Severity
    category: str
    file: str
    line: int
    message: str
    snippet: str
    source: FindingSource
    suggested_fix: str = ""

    # Phase 0 compatibility: callers that imported the previous module accessed
    # `f.rule` (the human rule name). The Phase 1 stable handle is `f.id` (e.g.
    # ES-PRINT-ENV-01); expose it under the old name so wrapper.py and any
    # external integrators keep working without a code change. See
    # handoff/reviewer_feedback.md MF-1.
    @property
    def rule(self) -> str:
        return self.id


@dataclass(slots=True)
class SkillManifest:
    name: str | None = None
    description: str | None = None
    declared_capabilities: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanReport:
    source: str
    skill_root: str
    manifest: SkillManifest
    files_scanned: int
    bytes_scanned: int
    findings: list[Finding]
    risk_score: int
    severity: OverallSeverity
    suggested_fix: str
    warnings: list[str]
    llm_used: bool
    duration_ms: int

    # Phase 0 compatibility: the previous ScanResult exposed `risk_label` ∈
    # {"clean", "low", "medium", "high"}. Phase 1 replaced that with the
    # human-facing `severity` ∈ {"Safe", "Warning", "High Risk"}. The legacy
    # label is derived from `risk_score` thresholds (not from `severity`) so
    # the existing app.py `label_color` dict — keyed on the Phase 0 vocabulary
    # — keeps resolving without a KeyError. See handoff/reviewer_feedback.md
    # MF-1. Thresholds: 0 → clean, 1–24 → low, 25–69 → medium, 70+ → high.
    @property
    def risk_label(self) -> str:
        if self.risk_score == 0:
            return "clean"
        if self.risk_score < 25:
            return "low"
        if self.risk_score < 70:
            return "medium"
        return "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "skill_root": self.skill_root,
            "manifest": asdict(self.manifest),
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "findings": [asdict(f) for f in self.findings],
            "risk_score": self.risk_score,
            "severity": self.severity,
            "risk_label": self.risk_label,
            "suggested_fix": self.suggested_fix,
            "warnings": list(self.warnings),
            "llm_used": self.llm_used,
            "duration_ms": self.duration_ms,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Pass A — static (regex + entropy + ignore directive)
# ---------------------------------------------------------------------------


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_QUOTED_LITERAL_RE = re.compile(r"""(['"])([A-Za-z0-9_\-+/=]{20,})\1""")


def scan_text(text: str, filename: str = "<input>") -> list[Finding]:
    """Backwards-compat helper: regex ruleset only, no entropy, no ignore.

    Used by wrapper.py POST /scan. New code should call scan_skill().
    """
    out: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in SECRET_PATTERNS.items():
            if pattern.search(line):
                out.append(_finding_from_static_rule(rule, filename, lineno, line))
    return out


def _finding_from_static_rule(rule: str, filename: str, lineno: int, line: str) -> Finding:
    rule_id, severity, category, fix = _STATIC_RULE_META.get(
        rule, ("ES-STATIC-UNKNOWN", "warning", "credential_leak", "")
    )
    snippet = line.strip()
    if len(snippet) > 200:
        snippet = snippet[:197] + "..."
    return Finding(
        id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        category=category,
        file=filename,
        line=lineno,
        message=f"{rule} matched on line {lineno}.",
        snippet=snippet,
        source="static",
        suggested_fix=fix,
    )


def _scan_static(file_path: Path, rel_path: str) -> list[Finding]:
    """Run Pass A on a single file. Honors `# estes: ignore` per line."""
    findings: list[Finding] = []
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    for lineno, line in enumerate(text.splitlines(), start=1):
        if IGNORE_DIRECTIVE_RE.search(line):
            continue
        for rule, pattern in SECRET_PATTERNS.items():
            if pattern.search(line):
                findings.append(_finding_from_static_rule(rule, rel_path, lineno, line))

        # Entropy pass on long quoted literals.
        for m in _QUOTED_LITERAL_RE.finditer(line):
            literal = m.group(2)
            if _shannon_entropy(literal) >= 4.5:
                snippet = line.strip()[:200]
                findings.append(
                    Finding(
                        id="ES-ENTROPY-01",
                        severity="warning",
                        category="possible_secret",
                        file=rel_path,
                        line=lineno,
                        message="High-entropy string literal looks like a secret.",
                        snippet=snippet,
                        source="static",
                        suggested_fix="If this is a secret, move it to env. If not, consider shortening it.",
                    )
                )
                break  # one entropy hit per line is plenty
    return findings


# ---------------------------------------------------------------------------
# Pass B — Python AST
# ---------------------------------------------------------------------------


def _flatten_attr(node: ast.AST) -> str | None:
    """Return dotted name for an attribute/name chain, or None."""
    parts: list[str] = []
    cur: ast.AST | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _is_url_literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value.startswith(("http://", "https://")):
            return node.value
    return None


def _matches_secret_path(path: str) -> bool:
    return any(rx.search(path) for rx in SECRET_FILE_GLOBS)


class _LeakVisitor(ast.NodeVisitor):
    """AST pass B. See _STATIC_RULE_META analogues for rule ids."""

    def __init__(self, file: str) -> None:
        self.file = file
        self.findings: list[Finding] = []
        # Local-name symbol table: names known to currently hold env-var values.
        self.env_names: set[str] = set()
        # Function we are currently inside (for ES-NET-PHONEHOME-01 reachability).
        self._function_touches_env: list[bool] = [False]

    # ---- bookkeeping ----------------------------------------------------

    def _enter_function(self) -> None:
        self._function_touches_env.append(False)

    def _exit_function(self) -> None:
        self._function_touches_env.pop()

    def _mark_env_touch(self) -> None:
        if self._function_touches_env:
            self._function_touches_env[-1] = True

    def _current_function_touches_env(self) -> bool:
        return any(self._function_touches_env)

    # ---- env detection --------------------------------------------------

    def _is_env_read(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Subscript):
            return _flatten_attr(node.value) == "os.environ"
        if isinstance(node, ast.Call):
            target = _flatten_attr(node.func)
            return target in {"os.environ.get", "os.getenv"}
        return False

    def _expr_touches_env(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if self._is_env_read(node):
            self._mark_env_touch()
            return True
        if isinstance(node, ast.Name) and node.id in self.env_names:
            self._mark_env_touch()
            return True
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue) and self._expr_touches_env(v.value):
                    return True
        if isinstance(node, ast.BinOp):
            return self._expr_touches_env(node.left) or self._expr_touches_env(node.right)
        if isinstance(node, ast.Call):
            for a in node.args:
                if self._expr_touches_env(a):
                    return True
            for kw in node.keywords:
                if self._expr_touches_env(kw.value):
                    return True
        return False

    def _call_touches_env(self, node: ast.Call) -> bool:
        for arg in node.args:
            if self._expr_touches_env(arg):
                return True
        for kw in node.keywords:
            if self._expr_touches_env(kw.value):
                return True
        return False

    # ---- visitors -------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._enter_function()
        try:
            self.generic_visit(node)
        finally:
            self._exit_function()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._enter_function()
        try:
            self.generic_visit(node)
        finally:
            self._exit_function()

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        # Bind locals that are direct env reads so subsequent uses stay tainted.
        if self._is_env_read(node.value):
            self._mark_env_touch()
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.env_names.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func_name = _flatten_attr(node.func)
        snippet = self._snippet(node)

        # ES-PRINT-ENV-01
        if func_name == "print" and self._call_touches_env(node):
            self._add(
                node, "ES-PRINT-ENV-01", "high", "credential_leak",
                "print() exposes environment variable contents to stdout, which "
                "agent frameworks inject into the LLM context.",
                snippet,
                "Remove the print or redact the env value before printing.",
            )

        # ES-LOG-ENV-01
        elif func_name and "." in func_name:
            head, _, method = func_name.rpartition(".")
            log_methods = {"debug", "info", "warning", "error", "critical", "exception"}
            log_namespaces = {"logger", "log", "logging"}
            head_root = head.split(".")[0]
            if head_root in log_namespaces and method in log_methods and self._call_touches_env(node):
                self._add(
                    node, "ES-LOG-ENV-01", "high", "credential_leak",
                    f"{func_name}() logs environment variable contents.",
                    snippet,
                    "Strip the env value from the log call.",
                )

        # ES-EXEC-01
        if func_name in {"eval", "exec", "__import__"} and node.args:
            first = node.args[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                self._add(
                    node, "ES-EXEC-01", "high", "dangerous_call",
                    f"{func_name}() called with a non-literal argument.",
                    snippet,
                    "Replace dynamic code execution with an explicit dispatch table.",
                )

        # ES-SUBPROC-SHELL-01
        if func_name and func_name.startswith("subprocess."):
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    self._add(
                        node, "ES-SUBPROC-SHELL-01", "warning", "dangerous_call",
                        f"{func_name}(..., shell=True) enables shell injection.",
                        snippet,
                        "Pass an argv list and drop shell=True.",
                    )

        # ES-OS-SYSTEM-01
        if func_name == "os.system":
            self._add(
                node, "ES-OS-SYSTEM-01", "warning", "dangerous_call",
                "os.system() invokes a shell with the given string.",
                snippet,
                "Use subprocess.run([...]) without shell=True instead.",
            )

        # ES-FILE-SECRET-READ-01
        if func_name == "open" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if _matches_secret_path(first.value):
                    self._add(
                        node, "ES-FILE-SECRET-READ-01", "high", "credential_leak",
                        f"open() reads a known credential path: {first.value!r}.",
                        snippet,
                        "Remove this read or move credentials into a vault.",
                    )

        # ES-NET-PHONEHOME-01: literal HTTP call inside a function that also
        # touches env vars. We record candidate calls and their function-touch
        # state at flush time via _post_visit_check (handled in scan).
        if func_name in {"requests.get", "requests.post", "urllib.request.urlopen"}:
            url = _is_url_literal(node.args[0]) if node.args else None
            if url:
                host = (urlparse(url).hostname or "").lower()
                if host and host not in NETWORK_ALLOWLIST and self._current_function_touches_env():
                    self._add(
                        node, "ES-NET-PHONEHOME-01", "warning", "exfiltration_risk",
                        f"Outbound HTTP to {host} from a function that touches env vars.",
                        snippet,
                        "Remove the network call or document and allowlist the destination.",
                    )

        self.generic_visit(node)

    # ---- helpers --------------------------------------------------------

    def _snippet(self, node: ast.AST) -> str:
        try:
            text = ast.unparse(node)
        except Exception:
            text = ""
        text = text.strip().replace("\n", " ")
        return text[:200]

    def _add(
        self,
        node: ast.AST,
        rule_id: str,
        severity: Severity,
        category: str,
        message: str,
        snippet: str,
        suggested_fix: str,
    ) -> None:
        self.findings.append(
            Finding(
                id=rule_id,
                severity=severity,
                category=category,
                file=self.file,
                line=getattr(node, "lineno", 0),
                message=message,
                snippet=snippet,
                source="ast",
                suggested_fix=suggested_fix,
            )
        )


def _scan_ast(file_path: Path, rel_path: str) -> list[Finding]:
    if file_path.suffix.lower() != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [
            Finding(
                id="ES-PARSE-ERR-01",
                severity="info",
                category="parse_error",
                file=rel_path,
                line=exc.lineno or 0,
                message=f"Could not parse Python source: {exc.msg}.",
                snippet="",
                source="ast",
                suggested_fix="",
            )
        ]
    visitor = _LeakVisitor(rel_path)
    visitor.visit(tree)
    return visitor.findings


# ---------------------------------------------------------------------------
# Pass C — LLM semantic check
# ---------------------------------------------------------------------------

LLM_SYSTEM_PROMPT = (
    "You are a security auditor reviewing a third-party AI agent skill. "
    "You will be given the skill's manifest and a concatenated dump of its "
    "source files. Look for mismatches between what the manifest claims "
    "and what the code actually does, with a focus on:\n"
    "  - undeclared credential or environment-variable access\n"
    "  - outbound network calls the manifest does not mention\n"
    "  - file-system reads of secrets (.env, ssh keys, .pem, etc.)\n"
    "  - capabilities the code exercises but the manifest does not declare\n"
    "Respond with a single JSON object and nothing else. Schema:\n"
    "{\n"
    '  "findings": [\n'
    '    {"id": "ES-SEM-...", "severity": "high|warning|info", '
    '"category": "semantic_mismatch", "file": "<relative path or empty>", '
    '"line": 0, "message": "<one sentence>", "snippet": "<<=200 chars>", '
    '"suggested_fix": "<one sentence>"}\n'
    "  ],\n"
    '  "summary": "<one sentence overall remediation, may be empty>"\n'
    "}\n"
    "If nothing is suspicious, return {\"findings\": [], \"summary\": \"\"}."
)


def _build_user_prompt(manifest: SkillManifest, code_dump: str, tree: str) -> str:
    manifest_text = manifest.description or "(no manifest description provided)"
    if len(manifest_text) > 4096:
        manifest_text = manifest_text[:4093] + "..."
    return (
        "SKILL MANIFEST:\n---\n"
        f"name: {manifest.name or '(unknown)'}\n"
        f"declared_capabilities: {manifest.declared_capabilities}\n"
        f"description: {manifest_text}\n"
        "---\n\n"
        "FILE TREE:\n"
        f"{tree}\n\n"
        "CODE (concatenated, truncated):\n"
        f"{code_dump}\n"
    )


def _build_code_dump(files: list[tuple[str, Path]], limit: int = 32_000) -> str:
    chunks: list[str] = []
    used = 0
    for rel, path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        header = f"\n# === {rel} ===\n"
        if used + len(header) >= limit:
            break
        remaining = limit - used - len(header)
        if remaining <= 0:
            break
        chunks.append(header + text[:remaining])
        used += len(header) + min(len(text), remaining)
        if used >= limit:
            break
    return "".join(chunks)


def _build_tree(files: list[tuple[str, Path]]) -> str:
    return "\n".join(rel for rel, _ in files[:200])


def _call_anthropic(model: str, api_key: str, system: str, user: str, timeout_s: float) -> str:
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 1024,
            "temperature": 0,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        },
        timeout=timeout_s,
    )
    resp.raise_for_status()
    data = resp.json()
    parts = data.get("content") or []
    for part in parts:
        if isinstance(part, dict) and part.get("type") == "text":
            return part.get("text", "")
    return ""


def _call_xai(model: str, api_key: str, system: str, user: str, timeout_s: float) -> str:
    resp = requests.post(
        "https://api.x.ai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 1024,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        },
        timeout=timeout_s,
    )
    resp.raise_for_status()
    data = resp.json()
    choices = data.get("choices") or []
    if choices and isinstance(choices[0], dict):
        msg = choices[0].get("message") or {}
        return msg.get("content", "") or ""
    return ""


_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_llm_json(raw: str) -> dict[str, Any] | None:
    """Tolerate code fences and chatter around the JSON object."""
    if not raw:
        return None
    text = raw.strip()
    if text.startswith("```"):
        # strip the fence
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = _JSON_BLOCK_RE.search(text)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None


def _coerce_llm_findings(blob: dict[str, Any]) -> tuple[list[Finding], str]:
    raw_findings = blob.get("findings")
    out: list[Finding] = []
    if isinstance(raw_findings, list):
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            sev = item.get("severity", "warning")
            if sev not in {"info", "warning", "high"}:
                sev = "warning"
            out.append(
                Finding(
                    id=str(item.get("id", "ES-SEM-LLM-01"))[:64],
                    severity=sev,  # type: ignore[arg-type]
                    category=str(item.get("category", "semantic_mismatch"))[:64],
                    file=str(item.get("file", ""))[:200],
                    line=int(item.get("line", 0) or 0),
                    message=str(item.get("message", ""))[:500],
                    snippet=str(item.get("snippet", ""))[:200],
                    source="llm",
                    suggested_fix=str(item.get("suggested_fix", ""))[:500],
                )
            )
    summary = str(blob.get("summary", ""))[:500]
    return out, summary


def _llm_semantic_check(
    manifest: SkillManifest,
    files: list[tuple[str, Path]],
    timeout_s: float,
) -> tuple[list[Finding], str, list[str], bool]:
    """Returns (findings, summary, warnings, llm_used)."""
    provider = os.environ.get("ESTES_LLM_PROVIDER", "anthropic").strip().lower()
    if provider == "off":
        return [], "", ["LLM check disabled (ESTES_LLM_PROVIDER=off)."], False

    if provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return [], "", ["LLM check skipped: ANTHROPIC_API_KEY not set."], False
        model = os.environ.get("ESTES_LLM_MODEL", "claude-haiku-4-5")
        caller = lambda u: _call_anthropic(model, api_key, LLM_SYSTEM_PROMPT, u, timeout_s)
    elif provider == "xai":
        api_key = os.environ.get("XAI_API_KEY")
        if not api_key:
            return [], "", ["LLM check skipped: XAI_API_KEY not set."], False
        model = os.environ.get("ESTES_LLM_MODEL", "grok-4-mini")
        caller = lambda u: _call_xai(model, api_key, LLM_SYSTEM_PROMPT, u, timeout_s)
    else:
        return [], "", [f"LLM check skipped: unknown provider {provider!r}."], False

    user_prompt = _build_user_prompt(
        manifest, _build_code_dump(files), _build_tree(files)
    )

    try:
        raw = caller(user_prompt)
    except requests.RequestException as exc:
        return [], "", [f"LLM check skipped: HTTP error: {exc}"], False
    except Exception as exc:  # noqa: BLE001
        return [], "", [f"LLM check skipped: {exc.__class__.__name__}: {exc}"], False

    blob = _parse_llm_json(raw)
    if not isinstance(blob, dict):
        return [], "", ["LLM check skipped: response was not valid JSON."], True

    findings, summary = _coerce_llm_findings(blob)
    return findings, summary, [], True


# ---------------------------------------------------------------------------
# Source resolution & extraction
# ---------------------------------------------------------------------------


_GITHUB_HOST_RE = re.compile(r"^https?://github\.com/", re.IGNORECASE)


def _is_github_url(s: str) -> bool:
    return bool(_GITHUB_HOST_RE.match(s))


def _parse_github_url(url: str) -> tuple[str, str, str | None, str | None] | None:
    """Returns (owner, repo, branch_or_None, subpath_or_None) or None on bad input."""
    m = re.match(
        r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/(.+?))?/?$",
        url,
    )
    if not m:
        return None
    owner, repo, rest = m.group(1), m.group(2), m.group(3)
    branch: str | None = None
    subpath: str | None = None
    if rest:
        parts = rest.split("/", 1)
        if parts[0] == "tree" and len(parts) == 2:
            tail = parts[1].split("/", 1)
            branch = tail[0]
            if len(tail) == 2 and tail[1]:
                subpath = tail[1]
        elif parts[0] in {"blob", "raw"}:
            tail = parts[1].split("/", 1) if len(parts) == 2 else []
            if tail:
                branch = tail[0]
                if len(tail) == 2:
                    subpath = tail[1]
    return owner, repo, branch, subpath


def _github_default_branch(owner: str, repo: str, timeout_s: float) -> str:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}",
        headers=headers,
        timeout=timeout_s,
    )
    resp.raise_for_status()
    return resp.json().get("default_branch", "main")


def _fetch_github_zip(
    owner: str,
    repo: str,
    branch: str,
    dest_zip: Path,
    timeout_s: float,
    max_bytes: int,
) -> None:
    """Stream a codeload zip to disk. Aborts and unlinks if the running total
    exceeds `max_bytes` — Content-Length is hostile-controlled and may be
    absent, so we count what we actually write. See MF-2.
    """
    headers: dict[str, str] = {}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
    resp = requests.get(url, headers=headers, timeout=timeout_s, stream=True)
    resp.raise_for_status()

    total = 0
    f = dest_zip.open("wb")
    try:
        for chunk in resp.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                f.close()
                dest_zip.unlink(missing_ok=True)
                raise requests.RequestException(
                    f"GitHub archive exceeded max_bytes={max_bytes}; "
                    f"aborted at {total} bytes."
                )
            f.write(chunk)
    finally:
        if not f.closed:
            f.close()


def _safe_extract(
    zip_path: Path, dest_dir: Path, max_bytes: int
) -> tuple[int, list[str]]:
    """Extract zip_path into dest_dir, defending against traversal & bombs."""
    warnings_out: list[str] = []
    total = 0
    per_file_cap = max_bytes // 4
    dest_resolved = dest_dir.resolve()

    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        return 0, [f"Not a valid zip: {zip_path.name}"]

    with zf:
        for info in zf.infolist():
            name = info.filename
            if not name or name.endswith("/"):
                continue
            # Reject absolute / traversal entries.
            if Path(name).is_absolute() or ".." in Path(name).parts:
                warnings_out.append(f"Skipped traversal entry: {name}")
                continue
            # Reject symlinks (high four bits == 0o12 -> S_IFLNK).
            if (info.external_attr >> 28) == 0o12:
                warnings_out.append(f"Skipped symlink entry: {name}")
                continue
            if info.file_size > per_file_cap:
                warnings_out.append(
                    f"Skipped oversized entry ({info.file_size} bytes): {name}"
                )
                continue
            if total + info.file_size > max_bytes:
                warnings_out.append(
                    f"Aborted extract at max_bytes={max_bytes}; remaining entries skipped."
                )
                break

            target = (dest_dir / name).resolve()
            try:
                target.relative_to(dest_resolved)
            except ValueError:
                warnings_out.append(f"Skipped escape entry: {name}")
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                data = src.read(per_file_cap + 1)
                if len(data) > per_file_cap:
                    warnings_out.append(
                        f"Skipped runtime-oversized entry: {name}"
                    )
                    target.unlink(missing_ok=True)
                    continue
                dst.write(data)
                total += len(data)

    return total, warnings_out


def _resolve_source(
    source: str | Path,
    workspace: Path,
    *,
    timeout_s: float,
    max_bytes: int,
) -> tuple[Path | None, list[str]]:
    """Materialize the skill into workspace/skill/. Returns (skill_root, warnings)."""
    warnings_out: list[str] = []
    skill_dir = workspace / "skill"
    skill_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = workspace / "source"
    raw_dir.mkdir(parents=True, exist_ok=True)

    src_str = str(source)

    # GitHub URL.
    if _is_github_url(src_str):
        parsed = _parse_github_url(src_str)
        if parsed is None:
            warnings_out.append(f"Could not parse GitHub URL: {src_str}")
            return None, warnings_out
        owner, repo, branch, subpath = parsed
        try:
            if branch is None:
                branch = _github_default_branch(owner, repo, timeout_s)
            archive_path = raw_dir / f"{repo}-{branch.replace('/', '_')}.zip"
            _fetch_github_zip(
                owner, repo, branch, archive_path, timeout_s, max_bytes
            )
        except requests.RequestException as exc:
            warnings_out.append(f"GitHub fetch failed: {exc}")
            return None, warnings_out
        _, extract_warnings = _safe_extract(archive_path, skill_dir, max_bytes)
        warnings_out.extend(extract_warnings)
        # codeload archives have a single top-level directory: <repo>-<branch>
        children = [p for p in skill_dir.iterdir() if p.is_dir()]
        root = children[0] if len(children) == 1 else skill_dir
        if subpath:
            candidate = (root / subpath).resolve()
            try:
                candidate.relative_to(root.resolve())
            except ValueError:
                warnings_out.append(f"Subpath escapes archive root: {subpath}")
                return None, warnings_out
            if not candidate.exists():
                warnings_out.append(f"Subpath not found in archive: {subpath}")
                return None, warnings_out
            root = candidate
        return root, warnings_out

    if src_str.startswith(("git@", "ssh://")):
        warnings_out.append("SSH git URLs are not supported in Phase 1.")
        return None, warnings_out

    # Local path.
    p = Path(src_str).expanduser()
    if not p.exists():
        warnings_out.append(f"Source not found: {p}")
        return None, warnings_out

    if p.is_file() and p.suffix.lower() == ".zip":
        _, extract_warnings = _safe_extract(p, skill_dir, max_bytes)
        warnings_out.extend(extract_warnings)
        children = [c for c in skill_dir.iterdir() if c.is_dir()]
        root = children[0] if len(children) == 1 else skill_dir
        return root, warnings_out

    if p.is_file():
        target = skill_dir / p.name
        target.write_bytes(p.read_bytes())
        return skill_dir, warnings_out

    if p.is_dir():
        # Copy without following symlinks to avoid escape via absolute targets.
        shutil.copytree(p, skill_dir, dirs_exist_ok=True, symlinks=False)
        return skill_dir, warnings_out

    warnings_out.append(f"Unsupported source shape: {p}")
    return None, warnings_out


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _discover_manifest(skill_root: Path) -> SkillManifest:
    for name in MANIFEST_NAMES:
        path = skill_root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if path.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-untyped]

                data = yaml.safe_load(text) or {}
            except Exception:
                data = {}
            if isinstance(data, dict):
                return SkillManifest(
                    name=str(data.get("name")) if data.get("name") else None,
                    description=str(data.get("description") or text[:4096]),
                    declared_capabilities=list(data.get("capabilities") or []),
                )

        if path.suffix.lower() == ".json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            if isinstance(data, dict):
                return SkillManifest(
                    name=str(data.get("name")) if data.get("name") else None,
                    description=str(data.get("description") or text[:4096]),
                    declared_capabilities=list(data.get("capabilities") or []),
                )

        # Markdown: pull first H1 as name, body as description.
        name_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        return SkillManifest(
            name=name_match.group(1).strip() if name_match else None,
            description=text[:4096],
            declared_capabilities=[],
        )

    return SkillManifest()


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SCANNABLE_SUFFIXES:
            yield path


def _discover_files(
    skill_root: Path, max_bytes: int
) -> tuple[list[tuple[str, Path]], int, list[Finding]]:
    files: list[tuple[str, Path]] = []
    bytes_used = 0
    oversize: list[Finding] = []
    for path in _iter_files(skill_root):
        rel = path.relative_to(skill_root).as_posix()
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > DEFAULT_PER_FILE_BYTES:
            oversize.append(
                Finding(
                    id="ES-FILE-OVERSIZE-01",
                    severity="info",
                    category="scan_skipped",
                    file=rel,
                    line=0,
                    message=f"File skipped: {size} bytes exceeds per-file cap ({DEFAULT_PER_FILE_BYTES}).",
                    snippet="",
                    source="static",
                    suggested_fix="",
                )
            )
            continue
        if bytes_used + size > max_bytes:
            break
        files.append((rel, path))
        bytes_used += size
    return files, bytes_used, oversize


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _compute_score(findings: list[Finding]) -> int:
    weights = {"high": 40, "warning": 12, "info": 3}
    total = sum(weights.get(f.severity, 0) for f in findings)
    return min(100, total)


def _compute_severity(findings: list[Finding], score: int) -> OverallSeverity:
    n_high = sum(1 for f in findings if f.severity == "high")
    n_warn = sum(1 for f in findings if f.severity == "warning")
    if n_high >= 1 or score >= 70:
        return "High Risk"
    if n_warn >= 1 or score >= 25:
        return "Warning"
    return "Safe"


def _rollup_suggested_fix(findings: list[Finding], llm_summary: str) -> str:
    n_high = sum(1 for f in findings if f.severity == "high")
    n_warn = sum(1 for f in findings if f.severity == "warning")
    if n_high:
        base = (
            f"Remove credential leaks before installing this skill. "
            f"See the {n_high} high-severity finding(s)."
        )
    elif n_warn:
        base = (
            f"Review the {n_warn} warning(s); this skill may exceed its "
            "declared capabilities."
        )
    else:
        base = "No actionable issues detected."
    if llm_summary:
        base = f"{base}\n{llm_summary}"
    return base


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.file, f.line, f.id)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_skill(
    source: str | Path,
    *,
    llm: bool = True,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> ScanReport:
    """Scan a skill from a local path, archive, or public GitHub URL."""
    started = time.monotonic()
    src_str = str(source)
    warnings_out: list[str] = []
    log.debug("scan_skill start: source=%s llm=%s", src_str, llm)

    with tempfile.TemporaryDirectory(prefix="estes_") as tmp:
        workspace = Path(tmp)
        skill_root, resolve_warnings = _resolve_source(
            source, workspace, timeout_s=timeout_s, max_bytes=max_bytes
        )
        warnings_out.extend(resolve_warnings)

        if skill_root is None:
            return ScanReport(
                source=src_str,
                skill_root="",
                manifest=SkillManifest(),
                files_scanned=0,
                bytes_scanned=0,
                findings=[],
                risk_score=0,
                severity="Safe",
                suggested_fix="No actionable issues detected.",
                warnings=warnings_out,
                llm_used=False,
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        manifest = _discover_manifest(skill_root)
        files, bytes_used, oversize = _discover_files(skill_root, max_bytes)

        findings: list[Finding] = list(oversize)
        for rel, path in files:
            findings.extend(_scan_static(path, rel))
            findings.extend(_scan_ast(path, rel))

        if not manifest.description:
            findings.append(
                Finding(
                    id="ES-MANIFEST-MISSING-01",
                    severity="warning",
                    category="manifest",
                    file="",
                    line=0,
                    message="No SKILL.md / manifest found at the skill root.",
                    snippet="",
                    source="static",
                    suggested_fix="Add a SKILL.md describing what the skill does and the data it touches.",
                )
            )

        llm_used = False
        llm_summary = ""
        if llm:
            llm_findings, llm_summary, llm_warnings, llm_used = _llm_semantic_check(
                manifest, files, timeout_s
            )
            findings.extend(llm_findings)
            warnings_out.extend(llm_warnings)

        findings = _dedupe(findings)
        score = _compute_score(findings)
        severity = _compute_severity(findings, score)
        suggested = _rollup_suggested_fix(findings, llm_summary)
        log.debug(
            "scan_skill done: severity=%s score=%d findings=%d files=%d",
            severity, score, len(findings), len(files),
        )

        return ScanReport(
            source=src_str,
            skill_root=str(skill_root.relative_to(workspace)),
            manifest=manifest,
            files_scanned=len(files),
            bytes_scanned=bytes_used,
            findings=findings,
            risk_score=score,
            severity=severity,
            suggested_fix=suggested,
            warnings=warnings_out,
            llm_used=llm_used,
            duration_ms=int((time.monotonic() - started) * 1000),
        )


def scan_path(root: str | Path) -> ScanReport:
    """Compatibility shim for Phase 0 callers (Streamlit + FastAPI)."""
    return scan_skill(root, llm=False)


def redact_text(text: str, marker: str = "[REDACTED by Estes]") -> tuple[str, int]:
    """Apply every Pass A regex to text. Returns (redacted_text, count)."""
    count = 0
    for pattern in SECRET_PATTERNS.values():
        text, n = pattern.subn(marker, text)
        count += n
    return text, count


__all__ = [
    "Finding",
    "ScanReport",
    "SkillManifest",
    "SECRET_PATTERNS",
    "redact_text",
    "scan_path",
    "scan_skill",
    "scan_text",
]
