# Modern, non-root Volatility 3 runtime. Legacy Vol2 has a separate Dockerfile.
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    PATH=/app/bin:$PATH M3MX_STATE_DIR=/app/state \
    XDG_CACHE_HOME=/app/state/cache HOME=/app/state
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 libffi8 \
    fonts-dejavu-core fontconfig shared-mime-info exiftool yara \
    file binutils xxd ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 m3mx && useradd --uid 10001 --gid m3mx --no-create-home m3mx
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip==26.2.2 \
    && pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
COPY static/ ./static/
COPY templates/ ./templates/
COPY rules/ ./rules/
COPY plugins.json gunicorn.conf.py ./
COPY bin/vol ./bin/vol
COPY LICENSE THIRD_PARTY_NOTICES.md ./
RUN chmod 755 /app/bin/vol && mkdir -p /app/uploads /app/outputs /app/state \
    && chown -R 10001:10001 /app/uploads /app/outputs /app/state
USER 10001:10001
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:5000/api/health || exit 1
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app.wsgi:application"]
