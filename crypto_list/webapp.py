from __future__ import annotations

import argparse
import contextlib
from pathlib import Path
from typing import *

from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

try:
    # Python 3.9+ compatible importlib.resources API
    from importlib.resources import files as ir_files
except Exception:  # pragma: no cover
    ir_files = None  # type: ignore


def _pkg_path(*parts: str) -> Path:
    """Resolve a package data directory/file to a concrete filesystem path.

    When the package is installed from a wheel, resources live inside the dist and
    importlib.resources is the right way to access them.
    """
    if ir_files is not None:
        ref = ir_files("crypto_list")
        for p in parts:
            ref = ref.joinpath(p)
        # Convert to a real filesystem path
        # Only call as_file() if available (i.e., ref is a Traversable)
        if hasattr(ref, "as_file"):
            with contextlib.ExitStack() as stack:
                path = stack.enter_context(ref.as_file())
                return Path(path)
        else:
            # ref is already a Path (e.g., PosixPath)
            return Path(ref)
    # Fallback: resolve relative to this file
    here = Path(__file__).resolve().parent
    return here.joinpath(*parts)


def create_app() -> FastAPI:
    app = FastAPI(title="crypto_list web", docs_url=None, redoc_url=None)

    web_dir = _pkg_path("web")
    icons_dir = _pkg_path("icons")

    # Mount static assets: the SPA and icons. No APIs for data; all crypto is client-side.
    app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")
    app.mount("/icons", StaticFiles(directory=str(icons_dir)), name="icons")

    @app.get("/health", response_class=HTMLResponse)
    def health() -> str:
        return "ok"

    @app.get("/", response_class=HTMLResponse)
    def index() -> FileResponse:
        return FileResponse(web_dir / "index.html")

    # Favicon
    @app.get("/favicon.ico")
    def favicon() -> FileResponse:
        return FileResponse(web_dir / "favicon.ico")

    return app


def main(argv: list[str] | None = None) -> None:
    # Lazy import to avoid uvicorn being required at import time
    import uvicorn
    parser = argparse.ArgumentParser(
        prog="crypto-list-webapp",
        description="Run the crypto_list web app (FastAPI + SPA)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    args = parser.parse_args(argv)

    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
