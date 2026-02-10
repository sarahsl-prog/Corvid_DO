"""Corvid FastAPI application entrypoint."""

from fastapi import FastAPI
from loguru import logger

from corvid.api.routes import analyses, iocs

app = FastAPI(
    title="Corvid",
    version="0.1.0",
    description="AI-powered cybersecurity threat intelligence platform",
)

# Register route modules
app.include_router(iocs.router, prefix="/api/v1")
app.include_router(analyses.router, prefix="/api/v1")

logger.info("Corvid API initialized")


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}
