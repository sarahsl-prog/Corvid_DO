"""Corvid FastAPI application entrypoint."""

import sys
import uuid
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from loguru import logger

from corvid.api.routes import analyses, iocs
from corvid.config import settings


def configure_logging() -> None:
    """Configure loguru for production or development."""
    # Remove default handler
    logger.remove()

    if settings.debug:
        # Development: human-readable format
        logger.add(
            sys.stdout,
            level="DEBUG",
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>",
            colorize=True,
        )
    else:
        # Production: JSON format for log aggregation
        logger.add(
            sys.stdout,
            level=settings.log_level,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
            serialize=True,  # JSON output
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    configure_logging()
    logger.info("Corvid API starting up")
    yield
    logger.info("Corvid API shutting down")


app = FastAPI(
    title="Corvid",
    version="0.1.0",
    description="AI-powered cybersecurity threat intelligence platform",
    lifespan=lifespan,
)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add request ID to each request for log correlation."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
    request.state.request_id = request_id

    with logger.contextualize(request_id=request_id):
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle uncaught exceptions with structured error response."""
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error("Unhandled exception: {} (request_id={})", exc, request_id)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.debug else "An unexpected error occurred",
            "request_id": request_id,
        },
    )


# Register route modules
app.include_router(iocs.router, prefix="/api/v1")
app.include_router(analyses.router, prefix="/api/v1")


@app.get("/health")
async def health() -> dict[str, Any]:
    """Health check endpoint with dependency status.

    Returns overall status and individual component checks.
    Status is "ok" if all checks pass, "degraded" otherwise.
    """
    checks = {
        "db": await check_db_connection(),
        "redis": await check_redis_connection(),
        "gradient": await check_gradient_connection(),
    }

    # Overall status
    all_ok = all(c["ok"] for c in checks.values())
    status = "ok" if all_ok else "degraded"

    return {
        "status": status,
        "checks": checks,
    }


async def check_db_connection() -> dict[str, Any]:
    """Check PostgreSQL database connectivity."""
    try:
        from sqlalchemy import text
        from corvid.db.session import async_session

        async with async_session() as session:
            await session.execute(text("SELECT 1"))
            return {"ok": True, "message": "Connected"}
    except Exception as e:
        logger.warning("Database health check failed: {}", e)
        return {"ok": False, "message": str(e)}


async def check_redis_connection() -> dict[str, Any]:
    """Check Redis connectivity."""
    try:
        import redis.asyncio as redis

        client = redis.from_url(settings.redis_url, decode_responses=True)
        await client.ping()
        await client.aclose()
        return {"ok": True, "message": "Connected"}
    except Exception as e:
        logger.warning("Redis health check failed: {}", e)
        return {"ok": False, "message": str(e)}


async def check_gradient_connection() -> dict[str, Any]:
    """Check Gradient AI API connectivity (if configured)."""
    if not settings.gradient_api_key:
        return {"ok": True, "message": "Not configured (optional)"}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Simple API connectivity check
            resp = await client.get(
                "https://api.gradient.ai/v1/models",
                headers={"Authorization": f"Bearer {settings.gradient_api_key}"},
            )
            if resp.status_code in (200, 401, 403):
                # 401/403 means API is reachable but key may be invalid
                return {"ok": True, "message": "API reachable"}
            return {"ok": False, "message": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("Gradient health check failed: {}", e)
        return {"ok": False, "message": str(e)}
