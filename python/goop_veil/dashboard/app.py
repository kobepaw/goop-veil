"""Dashboard app — FastAPI web interface for goop-veil monitoring.

Provides real-time status, detection results, and defense control.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def create_app():
    """Create the FastAPI dashboard application."""
    try:
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse
    except ImportError:
        raise ImportError(
            "Dashboard extras not installed: pip install goop-veil[dashboard]"
        )

    app = FastAPI(
        title="goop-veil",
        description="WiFi Privacy Defense Dashboard",
        version="0.1.0",
    )

    @app.get("/api/v1/status")
    async def get_status():
        from goop_veil._core import __version__ as core_version

        return JSONResponse({
            "status": "ok",
            "version": "0.1.0",
            "core_version": core_version,
        })

    @app.get("/api/v1/health")
    async def health():
        return JSONResponse({"healthy": True})

    return app
