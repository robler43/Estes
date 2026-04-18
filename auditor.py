"""SkillBouncer Auditor — static scanner for third-party agent skills.

Phase 0: minimal regex ruleset shared with the runtime wrapper.
Real entropy + AST passes land in a later phase.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

SCANNABLE_SUFFIXES = {
    ".py", ".js", ".ts", ".sh", ".rb", ".go",
    ".yaml", ".yml", ".json", ".env", ".toml", ".ini",
    ".md", ".txt",
}

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


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    snippet: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def risk_score(self) -> int:
        if not self.findings:
            return 0
        # Each finding contributes 20 points, capped at 100. Tunable in Phase 1.
        return min(100, len(self.findings) * 20)

    @property
    def risk_label(self) -> str:
        score = self.risk_score
        if score == 0:
            return "clean"
        if score < 40:
            return "low"
        if score < 80:
            return "medium"
        return "high"


def scan_text(text: str, filename: str = "<input>") -> list[Finding]:
    """Scan a single text blob and return findings."""
    out: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in SECRET_PATTERNS.items():
            if pattern.search(line):
                snippet = line.strip()
                if len(snippet) > 200:
                    snippet = snippet[:197] + "..."
                out.append(Finding(file=filename, line=lineno, rule=rule, snippet=snippet))
    return out


def _iter_targets(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in SCANNABLE_SUFFIXES:
            yield path


def scan_path(root: str | Path) -> ScanResult:
    """Scan a file or directory tree and return an aggregated ScanResult."""
    root_path = Path(root)
    result = ScanResult()
    for path in _iter_targets(root_path):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        result.files_scanned += 1
        result.findings.extend(scan_text(text, str(path)))
    return result


def redact_text(text: str, marker: str = "[REDACTED by SkillBouncer]") -> tuple[str, int]:
    """Apply every secret pattern to text. Returns (redacted_text, count)."""
    count = 0
    for pattern in SECRET_PATTERNS.values():
        text, n = pattern.subn(marker, text)
        count += n
    return text, count
