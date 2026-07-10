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
# Run as a non-root user.
RUN useradd --create-home --uid 10001 vulna
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin
COPY app ./app
COPY pyproject.toml README.md ./
USER vulna

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=5 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
