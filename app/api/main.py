"""FastAPI application factory + ASGI app for ThreatStream.

Run:  uvicorn app.api.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.api.deps import AppState, build_state
from app.api.routes import router

FRONTEND = Path(__file__).resolve().parents[2] / "frontend" / "index.html"


def create_app(state: AppState | None = None) -> FastAPI:
    app = FastAPI(
        title="ThreatStream Security Analytics",
        version="2.0.0",
        description="OCSF normalized multi-source security logs + correlation + RAG-grounded AI analysis",
    )
    app.state.app_state = state or build_state()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    app.include_router(router, prefix="/api/v1")

    @app.get("/api")
    def root_index():
        return {"name": "ThreatStream Security Analytics API",
                "docs": "/docs", "ui": "/", "health": "/api/v1/health"}

    @app.get("/", include_in_schema=False)
    def dashboard():
        if FRONTEND.is_file():
            return FileResponse(FRONTEND)
        return {"hint": "frontend/index.html missing; API is under /api/v1"}

    return app


app = create_app()
