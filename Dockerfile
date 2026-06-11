# M3MX — Memory Forensics Workbench
#
# Bullseye is the last Debian release that still ships python2 in apt;
# Volatility 2's 800+ legacy plugins still require python2, so we need it.
FROM python:3.12-slim-bullseye

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    VOL3_ALLOW_PARTIAL_DUMP=1 \
    PATH=/app/bin:$PATH

# System dependencies:
#   python2        — Volatility 2 runtime
#   yara           — for YARA scanning + agent yara tool
#   weasyprint deps (libcairo2, libpango-1.0-0, libpangoft2-1.0-0, libgdk-pixbuf-2.0-0,
#                    shared-mime-info, libffi, fonts-dejavu) — PDF rendering
#   exiftool       — file_extractor preview metadata
#   build-essential, libffi-dev, libssl-dev — wheels with native bits
RUN apt-get update && apt-get install -y --no-install-recommends \
        python2 python2-dev \
        yara \
        exiftool \
        libcairo2 libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf-2.0-0 \
        shared-mime-info libffi-dev libssl-dev \
        fonts-dejavu fonts-dejavu-core \
        build-essential \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python 3 deps — copy requirements first so pip layer can cache.
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt \
 && pip3 install --no-cache-dir volatility3==2.28.0 weasyprint==62.3 'pydyf==0.11.0' beautifulsoup4==4.12.3

# Python 2 deps for Volatility 2 plugin coverage. Bullseye no longer ships
# python-crypto / python-pycryptodome as apt packages, so we bootstrap pip2
# from the pip legacy mirror and install:
#   pycryptodome  — hashdump / lsadump / cachedump
#   distorm3      — disassembly for vad / malfind paths
#   yara-python   — yarascan (binds to libyara installed above)
#   pillow        — image-related plugins
#   openpyxl      — xlsx output renderer
RUN curl -fsSL https://bootstrap.pypa.io/pip/2.7/get-pip.py -o /tmp/get-pip-2.7.py \
 && python2 /tmp/get-pip-2.7.py --no-cache-dir \
 && pip2 install --no-cache-dir \
        pycryptodome distorm3 yara-python pillow openpyxl \
 && rm -f /tmp/get-pip-2.7.py

# Bring in the bundled binaries (Vol2 source + launchers). The volatility3
# package is already pip-installed above; bin/vol is a thin shim around it.
COPY bin/ /app/bin/
RUN chmod +x /app/bin/vol /app/bin/vol2

# Bring in the application code.
COPY app/        /app/app/
COPY static/     /app/static/
COPY templates/  /app/templates/
COPY rules/      /app/rules/
COPY plugins.json /app/plugins.json
COPY start.py    /app/start.py
COPY config.json /app/config.json

# Runtime mount points; bind-mounted by docker-compose so analyst data persists.
RUN mkdir -p /app/uploads /app/outputs

EXPOSE 5000

# Healthcheck hits the lightweight /api/health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:5000/api/health || exit 1

# Drive the Flask app directly (start.py launches a browser, which we don't
# want inside a container).
CMD ["python3", "-c", "from app.main import create_app; \
import os; \
vp = {'vol2': os.environ.get('VOL2_PATH', '/app/bin/vol2'), \
       'vol3': os.environ.get('VOL3_PATH', '/app/bin/vol')}; \
app = create_app(volatility_paths=vp); \
app.run(host='0.0.0.0', port=5000, threaded=True, use_reloader=False)"]
