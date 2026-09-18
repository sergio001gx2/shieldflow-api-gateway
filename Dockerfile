# ─────────────────────────────────────────────────────────────────────────────
# ShieldFlow — Multi-Stage Dockerfile
# ─────────────────────────────────────────────────────────────────────────────
# Stages:
#   base        — Common Python base
#   development — Hot-reload dev server (mounted source)
#   production  — Optimized, non-root, minimal image
#
# Usage:
#   # Production:
#   docker build --target production -t shieldflow:latest .
#   docker run -p 8000:8000 --env-file .env shieldflow:latest
#
#   # Development (via docker-compose):
#   docker-compose up --build

# ── Base stage ────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

# Security: run as non-root in production
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Dependencies stage ────────────────────────────────────────────────────────
FROM base AS deps

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Development stage ─────────────────────────────────────────────────────────
FROM deps AS development

# Source is mounted as a volume in docker-compose.yml
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--reload", \
     "--log-level", "info"]

# ── Production stage ──────────────────────────────────────────────────────────
FROM deps AS production

# Create non-root user for security
RUN groupadd -r shieldflow && useradd -r -g shieldflow -s /sbin/nologin shieldflow

# Copy application source
COPY --chown=shieldflow:shieldflow . .

# Remove development/test files
RUN rm -rf tests/ locustfile.py .env.example \
    && find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true \
    && find . -name "*.pyc" -delete

USER shieldflow

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production server: multiple workers, no reload
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--log-level", "warning", \
     "--no-access-log"]
