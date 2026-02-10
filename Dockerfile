# Corvid Threat Intelligence Platform
# Multi-stage build for production deployment

# ============================================
# Stage 1: Builder
# ============================================
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir /app/wheels .

# ============================================
# Stage 2: Production
# ============================================
FROM python:3.12-slim as production

# Create non-root user for security
RUN groupadd --gid 1000 corvid && \
    useradd --uid 1000 --gid corvid --shell /bin/bash --create-home corvid

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels from builder and install
COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application code
COPY --chown=corvid:corvid corvid/ ./corvid/
COPY --chown=corvid:corvid alembic.ini .
COPY --chown=corvid:corvid pyproject.toml .

# Switch to non-root user
USER corvid

# Environment defaults (can be overridden)
ENV CORVID_DEBUG=false \
    CORVID_LOG_LEVEL=INFO \
    CORVID_API_HOST=0.0.0.0 \
    CORVID_API_PORT=8000

# Expose the API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["python", "-m", "uvicorn", "corvid.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
