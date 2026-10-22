FROM python:3.11-slim

# ── System dependencies (cached layer) ─────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt-dev \
    curl \
    cron \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libatspi2.0-0 \
    fonts-liberation \
    libffi-dev \
    libjpeg-dev \
    zlib1g-dev \
    nmap \
    gobuster \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ ./scripts/

# ── Python dependencies (cached layer — copy only pyproject.toml first) ───
COPY pyproject.toml ./
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[all]" && \
    playwright install chromium && \
    mkdir -p /app/data/ke_reports /app/models


# Train the NLP threat classifier during build so the model artifact is baked
# into the image (graceful degradation if network is unavailable).
ENV PYTHONPATH=/app/src
RUN python scripts/train_nlp_model.py

# Cron job: run fetch_historical_api.py every 24 hours to keep Kenya data fresh.
COPY config/crontab /etc/cron.d/historical-fetch
RUN chmod 0644 /etc/cron.d/historical-fetch && crontab /etc/cron.d/historical-fetch

RUN useradd -m -u 1000 appuser \
    && chown -R appuser:appuser /app /ms-playwright /app/models

USER appuser

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

EXPOSE 8080

CMD cron && python -m darkweb_scanner.main --help
