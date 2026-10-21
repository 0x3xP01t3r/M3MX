# Migration and operating notes

## Settings and secrets

`config.example.json` documents nonsecret defaults. Actual settings are in
`.m3mx/config.json`, keys in `.m3mx/secrets.json`, and chat history in the same
private state directory. `M3MX_STATE_DIR` overrides the directory. Secrets
files are mode 0600; this is OS access control, not encryption at rest.
Prefer environment keys such as `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`GOOGLE_API_KEY`, `GLM_API_KEY`, `AGENTROUTER_API_KEY`, `ABUSEIPDB_API_KEY`,
and `VIRUSTOTAL_API_KEY`. `ABUSEIPDB_KEY` and `VT_API_KEY` remain aliases.

An existing root `config.json` is read as a migration source when the new
state file is absent. Its keys are moved into the private secret store and
removed from the legacy file. Existing settings without security policy
version 1 cannot enable command tools. Re-enable them deliberately in Settings
after reviewing the new allowlist. Commands still need individual UI approval.
No analyst evidence or existing report files are deleted by migration.

Environment keys take precedence over stored keys. Entering a new key in
Settings updates the private secret store; masked placeholders do not replace
keys. The real configuration and state directory are excluded from Git and
Docker builds. If old keys were previously committed or baked into images,
rotate them and address the old history/images separately.

## Native installation

Python 3.11+ on Linux is required. Use a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python start.py
```

Install Pango/Harfbuzz and fonts for PDF rendering; `yara`, `exiftool`, `file`,
and `xxd` provide optional forensic capabilities. The launcher runs one
threaded Gunicorn worker on `127.0.0.1:5000`. Use `M3MX_PORT` for another port.
Do not add multiple Gunicorn workers: loaded-image/status state is in-process.
`VOL3_PATH` and `VOL2_PATH` select trusted launch-time executables. Browser
settings cannot change executable paths. Native Vol2 fallback is available
only if Python 2 and its required dependencies are installed separately.

## Docker

```sh
docker compose up -d --build
```

The modern image contains Volatility 3, runs as UID/GID 10001, drops
capabilities, prohibits privilege escalation, has a read-only root filesystem,
and publishes only loopback. Named volumes `m3mx-uploads`, `m3mx-outputs`, and
`m3mx-state` avoid host-directory ownership problems; Compose prefixes their
actual names with the project name. Rules are mounted read-only.
Use the UI to download results. Existing host `uploads/` and `outputs/` are
preserved but are not automatically imported into the new named volumes.
To reuse host bind mounts, explicitly configure an override and provision
those directories for UID/GID 10001. Never recursively change ownership of a
home directory or unrelated evidence collection.

The Compose memory limit is 4 GiB and the CPU limit is 2 cores. Adjust these
for representative images. Multipart temporary files stay on the disk-backed
upload volume; `/tmp` is a small tmpfs. The default upload limit is 64 GiB;
`M3MX_MAX_UPLOAD_BYTES` overrides it. Subprocess output defaults to 64 MiB;
`M3MX_PROCESS_OUTPUT_BYTES` can increase it up to 256 MiB.

Host Ollama is approved explicitly as `http://host.docker.internal:11434` by
Compose. Native localhost Ollama needs no extra configuration. For another
destination, set both the URL and its launch-time allowlist, for example:

```sh
export M3MX_OLLAMA_ENDPOINTS=http://127.0.0.1:11435
export M3MX_OLLAMA_URL=http://127.0.0.1:11435
```

`M3MX_GLM_ENDPOINTS` and `M3MX_AGENTROUTER_ENDPOINTS` work similarly for custom
bases. Allowlists are comma-separated exact scheme/host/port/base-path values.
Redirects are not accepted. Only approve services under your control.

## File roots and API clients

Default roots are `uploads/`, `outputs/`, and `rules/`. Register additional
directories before starting with `M3MX_EVIDENCE_ROOTS`, `M3MX_OUTPUT_ROOTS`, or
`M3MX_RULES_ROOTS` (OS-path-separator lists). Selecting an output folder in the
browser cannot expand these roots. Rule files remain read-only to agent tools.

Unsafe API requests now require the same-origin page's `m3mx-token` meta value
in `X-M3MX-Token`. Tokens expire when the process restarts. Browser requests
use `static/js/requests.js`; uploads and SSE POSTs receive the same protection.
Unexpected Origin or Host values are rejected, including on read endpoints.
The token is a local browser protection, not a replacement for network auth.

## Output compatibility

Routes, finding fields, Full Analysis SSE event names, and report basenames
are preserved. Files are now under:

```text
uploads/<evidence-id>/<original-filename>
uploads/<evidence-id>/manifest.json
outputs/full_analysis/<image-evidence-key>/<run-id>/findings.jsonl
outputs/full_analysis/<image-evidence-key>/<run-id>/manifest.json
outputs/extracted/<image-evidence-key>/<extraction-id>/...
```

Manual plugin JSON contains the evidence key and run ID. Reports filter plugin
outputs by the loaded evidence key instead of combining images with the same
filename. Older case directories remain readable through the legacy lookup;
their historical identity cannot be reconstructed with certainty. New runs
never overwrite them. A current-run pointer selects the latest run for an
image; older runs remain on disk.

The frontend is split into core/manual helpers, agent, Full Analysis,
extractor, and initialization/workflows. Filesystem routes have their own
Blueprint. No inline event handlers or remote fonts/icons are required.

## Legacy Vol2 CLI

Build the optional image only when compatibility requires it:

```sh
docker build -f Dockerfile.vol2 -t m3mx-vol2:legacy .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp \
  -v /absolute/evidence:/evidence:ro \
  m3mx-vol2:legacy -f /evidence/memory.raw imageinfo
```

This isolated CLI does not provide the web image with automatic Vol2 fallback.
It has Python 2's EOL risks and only a minimal dependency set; not every Vol2
plugin is supported. The bundled GPL notices remain intact. Downloading code
during a build is not used as a substitute for documenting distributed licenses.
