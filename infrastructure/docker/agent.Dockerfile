# syntax=docker/dockerfile:1.7
# Stage 1: Builder with full toolchain
FROM python:3.11-slim-bookworm as builder

# System dependencies for compiled packages
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    cargo \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Configure Poetry
ENV POETRY_VERSION=1.7.1 \
    POETRY_HOME=/opt/poetry \
    POETRY_VIRTUALENVS_CREATE=false \
    PIP_NO_CACHE_DIR=1
ENV PATH="$POETRY_HOME/bin:$PATH"

# Install Poetry with separate layer
RUN --mount=type=cache,target=/root/.cache \
    curl -sSL https://install.python-poetry.org | python3 -

# Install Python dependencies
WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN --mount=type=cache,target=/root/.cache \
    poetry install --no-root --only main --sync -vvv \
    --extras "encryption monitoring"

# Stage 2: Runtime optimized image
FROM python:3.11-slim-bookworm as runtime

# Runtime dependencies
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends \
    libgomp1 \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user security context
RUN useradd -u 1001 -d /app -s /bin/false samsara
USER samsara
WORKDIR /app
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Copy artifacts from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --chown=samsara . /app

# Security hardening
RUN chmod -R 750 /app && \
    find /app -type f -name '*.py' -exec chmod 640 {} + && \
    chmod 644 /app/poetry.lock

# Stage 3: Production image with security scanning
FROM runtime as production

# Install security scanners (Trivy + Grype)
USER root
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
    && apt-get purge -y curl gnupg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Switch back to non-root user
USER samsara

# Health check and monitoring endpoint
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:9100/health || exit 1

# Runtime configuration
EXPOSE 9100 9115
ENTRYPOINT ["/app/entrypoints/agent_entrypoint.sh"]
CMD ["gunicorn", "samsara_ai.api.app:create_app()", \
    "--bind", "0.0.0.0:9100", \
    "--worker-class", "uvicorn.workers.UvicornWorker", \
    "--workers", "4", \
    "--timeout", "120", \
    "--access-logfile", "-", \
    "--error-logfile", "-", \
    "--capture-output"]
