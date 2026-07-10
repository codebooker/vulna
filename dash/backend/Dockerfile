# syntax=docker/dockerfile:1

# ---- Base ----
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app

# curl is used only by the container health check.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# ---- Dependencies ----
FROM base AS deps
COPY pyproject.toml README.md ./
# Copy the package so the project (and its pinned deps) can be installed.
COPY app ./app
RUN pip install --upgrade pip && pip install .

# ---- Runtime ----
FROM base AS runtime
# Run as a non-root user. Pre-create the data directories owned by that user so
# empty named volumes mounted onto them inherit non-root ownership on first use
# (keys, bootstrap token, reports, evidence).
RUN useradd --create-home --uid 10001 vulna \
    && mkdir -p /var/lib/vulna/keys /var/lib/vulna/bootstrap \
       /var/lib/vulna/reports /var/lib/vulna/evidence \
    && chown -R vulna:vulna /var/lib/vulna
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin
COPY app ./app
# Ship Alembic config and migrations so `alembic upgrade head` runs in-container.
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic
COPY pyproject.toml README.md ./
# Entrypoint applies migrations (idempotent) before serving; see docker-entrypoint.sh.
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh
USER vulna

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=5 \
    CMD curl -fsS http://localhost:8000/health || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
