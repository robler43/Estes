"""Estes Runtime Wrapper.

A FastAPI service that accepts skill output and returns a redacted version
before it reaches the LLM context. Phase 0 exposes a single /redact endpoint
backed by the same ruleset as the Auditor.

Run with: uvicorn wrapper:app --reload
"""
from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from auditor import redact_text, scan_text

app = FastAPI(title="Estes Runtime Wrapper", version="0.1.0")


class RedactRequest(BaseModel):
    output: str = Field(..., description="Raw stdout/stderr captured from a skill")


class RedactResponse(BaseModel):
    output: str
    redactions: int


class ScanRequest(BaseModel):
    text: str
    filename: str = "<input>"


class ScanFinding(BaseModel):
    file: str
    line: int
    rule: str
    snippet: str


class ScanResponse(BaseModel):
    findings: list[ScanFinding]


@app.get("/")
def root() -> dict[str, object]:
    return {"name": "Estes Runtime Wrapper", "phase": 0}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/redact", response_model=RedactResponse)
def redact(req: RedactRequest) -> RedactResponse:
    redacted, count = redact_text(req.output)
    return RedactResponse(output=redacted, redactions=count)


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    findings = scan_text(req.text, req.filename)
    return ScanResponse(
        findings=[
            ScanFinding(file=f.file, line=f.line, rule=f.rule, snippet=f.snippet)
            for f in findings
        ]
    )
