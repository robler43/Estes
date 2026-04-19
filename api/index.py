"""Vercel serverless entrypoint.

Vercel's @vercel/python builder picks up `api/*.py` files automatically and,
when the module exposes a callable named `app` that implements ASGI, mounts
it at the route declared in `vercel.json`.

This file just re-exports the FastAPI app defined in `web/server.py` so the
deploy story stays "one server, two front doors":

    local dev:  uvicorn web.server:app --reload --port 5173
    vercel:     POST /api/...  → api/index.py → web.server.app
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web.server import app  # noqa: E402,F401
