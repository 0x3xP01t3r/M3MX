# M3MX

Local memory-forensics workbench for Volatility 3, with manual analysis,
automated rules, correlated timelines, file extraction, reports, and an
optional AI assistant. Developed as a Computer Science graduation project at
Tafila Technical University. Project website: [m3mx.xyz](https://www.m3mx.xyz/).

M3MX is intended for one analyst on a local machine. The native launcher and
default Docker publication use localhost. See [SECURITY.md](SECURITY.md) before
changing that deployment boundary.

## Start with Docker

```sh
docker compose up -d --build
```

Open `http://127.0.0.1:5000`. The modern container runs as a non-root user,
uses Gunicorn, drops Linux capabilities, and has a read-only root filesystem.
Named volumes persist images, outputs, and private settings without requiring
host-folder ownership changes. Rules are mounted read-only.

Compose approves host Ollama at `http://host.docker.internal:11434`. Start an
Ollama daemon on the host if you want local AI. Other providers require their
own credentials. Native and Docker use the same pinned Python requirements.

## Native installation

Python 3.11+ and Linux are required. On Debian-based systems:

```sh
sudo apt install python3 python3-venv libpango-1.0-0 libpangoft2-1.0-0 \
  libharfbuzz-subset0 fonts-dejavu-core
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python start.py
```

Optional system tools: `yara`, `exiftool`, `file`, `binutils`, `xxd`, and
`zenity`. Native startup uses one threaded Gunicorn worker on loopback;
`M3MX_PORT` selects another port. `VOL3_PATH` selects a trusted Volatility
executable. Python 2 is not required for the default application.

Volatility 2 remains an optional legacy native fallback or isolated CLI
container. Its EOL runtime is deliberately excluded from the modern web image.
See [migration and legacy instructions](docs/MIGRATION.md).

## Investigation workflow

1. Upload an image. M3MX assigns an evidence ID and records a streaming SHA-256
   hash; uploading does not start analysis.
2. Choose Manual Analysis, Quick Triage, an Automation Workflow, or Full Analysis.
3. Review raw results, rule findings, confidence, MITRE mappings, correlations,
   limitations, and timeline events.
4. Extract files and inspect bounded hex/strings/metadata previews.
5. Generate deterministic reports or explicitly request an AI narrative/report.

Full Analysis V2 defaults on. Its OS detection, plugin planning, execution,
normalization, rules, scoring, mapping, correlation, timeline, and reporting
stages preserve the existing finding and SSE schemas. Each explicit run gets
its own output directory; reruns do not overwrite prior investigations.

The AI assistant supports OpenAI, Anthropic, Google Gen AI, GLM, AgentRouter,
and local Ollama. Agent command tools default off. When enabled, only
allowlisted read-only commands can be proposed, and the analyst must approve
each exact command in the browser. There is no general shell or interpreter
capability. External OSINT tools are separately disabled by default.
Report generation and automation synthesis cannot execute agent tools.

## Settings and evidence storage

Public defaults: [config.example.json](config.example.json).
Actual native settings and secrets: `.m3mx/`, excluded from Git and Docker.
Keys are stored separately with mode 0600, or supplied through environment
variables, which take priority. The browser receives only configured markers.

```text
app/                 Flask backend, security policies, runners, reports
app/fa2/             Normalizers, rules, scoring, MITRE, correlations, timeline
app/routes/          Route groups, including confined filesystem operations
rules/               YAML detection rules and baselines; optional YARA rules
templates/           HTML interface without inline script handlers
static/js/           Shared requests, core/manual, agent, analysis, extractor, workflows
static/vendor/       Local fonts/icons and their license notices
uploads/             Native evidence, unique IDs, SHA-256 manifests
outputs/             Native plugin outputs, separate analysis runs, extracted files
tests/               Synthetic fixtures and security/regression tests
```

Register extra trusted roots and AI services at launch, not through model
arguments. The [migration guide](docs/MIGRATION.md) explains those variables,
old-config migration, Docker volumes, resource limits, and compatibility.

## API

Existing route names are preserved. Every unsafe request requires
`X-M3MX-Token` from the same-origin page's `m3mx-token` meta element. Host and
Origin checks apply to read endpoints too. This is local browser protection,
not multi-user authentication.

| Routes | Purpose |
|---|---|
| `/api/health`, `/api/status`, `/api/loaded-image` | Runtime status |
| `/api/settings`, `/api/ollama/models` | Settings and approved local model discovery |
| `/api/upload` | Upload only; unique image and SHA-256 manifest |
| `/api/plugins`, `/api/run-plugin`, `/api/run-plugin/stream` | Plugin registry and execution |
| `/api/triage`, `/api/full-analysis` | Explicit triage and Full Analysis |
| `/api/full-analysis/case`, `/ai-report`, `/export-pdf` | Case reload, optional AI report, deterministic PDF export |
| `/api/files/scan`, `/preview`, `/extract`, `/raw` | Extraction and safe previews/downloads |
| `/api/outputs`, `/view`, `/download`, `/delete` | Saved output management |
| `/api/reports/generate` | Report-only AI synthesis and export |
| `/api/agent/chat`, `/history`, `/test`, `/reset`, `/approve` | Agent and one-use command approval |
| `/api/fs/browse`, `/mkdir`, `/pick-dir-native` | Approved output directories only |

Rows with abbreviated suffixes share the first route's prefix.
See [the compatibility contract](app/fa2/CONTRACT.md) for event and finding fields.

## Verification

```sh
pip install -r requirements-dev.txt
pytest -q
bandit -q -r app start.py -ll
pip-audit --progress-spinner off
docker compose config --quiet
```

Tests use temporary directories and synthetic evidence. They check request
protection, paths/symlinks, secrets, command approvals, SSRF, upload identity,
stream cleanup, cache invalidation, normalizers, rules, and real PDF rendering.
GitHub Actions runs tests, security/dependency scans, and hardened Docker startup.
Real-image accuracy and performance require representative analyst fixtures.

For a local browser smoke test, install `requirements-browser.txt` and run
`python tests/browser_smoke.py http://127.0.0.1:5057` against an isolated fixture
server. It uploads synthetic data and saves settings; do not point it at an
active investigation. See [the prompt injection demonstration](docs/PROMPT_INJECTION_DEMO.md)
for tests that deliberately simulate a model following hostile artifact text.

## License and acknowledgments

First-party M3MX code is MIT licensed. Third-party components retain their own
licenses; Volatility 2 is GPL-2.0-or-later, and Volatility 3 uses VSL. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the bundled notices.

Thanks to the project teammates for their effort and dedication, and to
Dr. Ibrahim Altarawneh for his guidance and support.
