"""Web API and static front end."""
from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .netguard import TargetError
from .report import build_pdf
from .scanner import scan

log = logging.getLogger("securecheck")
STATIC = Path(__file__).resolve().parent.parent / "static"

PER_IP_LIMIT = int(os.environ.get("SECURECHECK_RATE_PER_IP", "10"))      # scans per minute
GLOBAL_LIMIT = int(os.environ.get("SECURECHECK_RATE_GLOBAL", "60"))      # scans per minute
MAX_CONCURRENT = int(os.environ.get("SECURECHECK_MAX_CONCURRENT", "8"))
CACHE_SECONDS = 300

# The scanner holds itself to the standard it checks for.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class RateLimiter:
    """Sliding-window limiter, in memory. Fine for a single instance."""

    def __init__(self, limit: int, window: float = 60.0):
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 10_000:  # bound memory under an address flood
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


def create_app() -> FastAPI:
    app = FastAPI(title="SecureCheck", docs_url=None, redoc_url=None, openapi_url=None)
    per_ip = RateLimiter(PER_IP_LIMIT)
    everyone = RateLimiter(GLOBAL_LIMIT)
    slots = threading.BoundedSemaphore(MAX_CONCURRENT)
    cache: dict[str, tuple[float, dict]] = {}
    cache_lock = threading.Lock()

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        path = request.url.path
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        elif path.startswith("/fonts/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            # Pages, scripts and styles: always revalidate, so a new release is
            # never mixed with stale files held by a browser or CDN.
            response.headers["Cache-Control"] = "no-cache"
        return response

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    def get_result(url: str, request: Request):
        """Shared by the scan and report endpoints. Returns (result, error_response)."""
        client = request.client.host if request.client else "unknown"
        if not per_ip.allow(client) or not everyone.allow("*"):
            return None, JSONResponse({"error": "Too many scans. Wait a minute and try again."}, 429,
                                      headers={"Retry-After": "60"})

        key = url.strip().lower()
        with cache_lock:
            hit = cache.get(key)
            if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
                return {**hit[1], "cached": True}, None

        if not slots.acquire(timeout=5):
            return None, JSONResponse({"error": "The scanner is busy. Try again in a moment."}, 503)
        try:
            result = scan(url)
        except TargetError as exc:
            return None, JSONResponse({"error": str(exc)}, 400)
        except Exception:
            # Never return internal error text to the caller.
            log.exception("scan failed")
            return None, JSONResponse({"error": "The scan failed unexpectedly. Try again."}, 500)
        finally:
            slots.release()

        with cache_lock:
            if len(cache) > 500:
                cache.clear()
            cache[key] = (time.monotonic(), result)
            cache["pdf:" + result["host"]] = (time.monotonic(), result)  # lets the report reuse this scan
        return {**result, "cached": False}, None

    @app.post("/api/scan")
    def run_scan(body: ScanRequest, request: Request):
        result, error = get_result(body.url, request)
        return error if error is not None else result

    @app.post("/api/report")
    def run_report(body: ScanRequest, request: Request):
        """PDF report. Built from the server's own scan result, never from client-supplied data."""
        with cache_lock:
            hit = cache.get("pdf:" + body.url.strip().lower())
        if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
            result, error = hit[1], None
        else:
            result, error = get_result(body.url, request)
        if error is not None:
            return error
        try:
            pdf = build_pdf(result)
        except Exception:
            log.exception("report failed")
            return JSONResponse({"error": "The report could not be created. Try again."}, 500)
        name = "".join(c if c.isalnum() or c in ".-" else "-" for c in result["host"])[:80]
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="securecheck-{name}.pdf"'})

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/", StaticFiles(directory=STATIC), name="static")
    return app


app = create_app()
