<!-- markdownlint-disable -->

<div align="center">

# m3mx CORTEX

**An AI-augmented memory forensics workbench for Volatility 3 / 2.**

A web-based DFIR platform that wraps the full Volatility plugin catalogue with an LLM agent, automated triage, MITRE ATT&CK mapping, file extraction, and on-demand PDF reporting.

[![Volatility](https://img.shields.io/badge/volatility-3.x%20%2F%202.x-38bdf8)](https://github.com/volatilityfoundation/volatility3)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776ab)](https://www.python.org)
[![Flask](https://img.shields.io/badge/flask-3.0-000000)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/license-MIT-10b981)](LICENSE)
[![Plugins](https://img.shields.io/badge/plugins-178-f59e0b)](plugins.json)

</div>

---

## Contents

1. [What it does](#what-it-does)
2. [Architecture](#architecture)
3. [Quick start (Docker — recommended)](#quick-start-docker--recommended)
4. [Quick start (native)](#quick-start-native)
5. [Configuration](#configuration)
6. [Security notes](#security-notes)
7. [Workflow walkthrough](#workflow-walkthrough)
8. [The AI agent](#the-ai-agent)
9. [API reference](#api-reference)
10. [Project layout](#project-layout)
11. [Troubleshooting](#troubleshooting)
12. [Contributing & License](#contributing--license)

---

## What it does

m3mx is an opinionated front-end + orchestration layer over **Volatility 3** (with **Volatility 2** as a fallback) plus a tool-using **LLM agent**. The goal is to compress an analyst's memory-forensics workflow into a single browser tab without giving up control.

**Capabilities**

- **One-click Full Analysis** — runs a curated battery of high-signal plugins in sequence, applies a small rule engine to the parsed output, and streams findings into the UI in real time.
- **AI Attack Story** — a senior-DFIR-style narrative is generated from the findings (Initial Access → Execution → Persistence → Defense Evasion → Discovery / Lateral / Exfil → IOCs), citing finding IDs inline.
- **Manual Analysis** — every plugin in `plugins.json` (178 entries) is searchable, filterable, and runnable; results render in a sortable table with auto-detected severity / MITRE / tags / confidence pills.
- **AI Agent (chat)** — conversational ReAct loop with 9 tools: `run_volatility`, `run_shell`, `read_file`, `list_outputs`, `read_output`, `web_search` (DuckDuckGo), `threat_intel` (AbuseIPDB / VirusTotal), `yara_scan`, `generate_report`. Emits live `tool_call`/`tool_result` SSE events to the UI.
- **File Extractor** — runs `windows.filescan`, builds a tree, previews any file as hex + strings + metadata, extracts to disk.
- **Automation Workflows** — pre-built playbooks (Malware Triage, Credential Hunt, Network Recon, Full Sweep) execute a chain of plugins and finish with an *analyst-only* AI synthesis step.
- **PDF Report** — on-demand only. Renders findings + attack story to a print-ready PDF via WeasyPrint.
- **Multi-provider LLM** — OpenAI, Anthropic, Google Gemini, ZhipuAI GLM, agentrouter.org (Claude/DeepSeek/GLM proxy), Ollama (local). Configurable per-session.

**Volatility quality-of-life**

- **Vol2 auto-profile** — `imageinfo` runs once per image and caches the suggested profile so subsequent Vol2 plugins inherit `--profile=` automatically.
- **Vol3 partial-dump support** — a small patch to Vol3's `WindowsIntelStacker` (gated by `VOL3_ALLOW_PARTIAL_DUMP=1`) allows partial / truncated dumps to build a layer instead of hard-failing.
- **v3 → v2 auto-fallback** — when Vol3's layer-stack rejects an image but the plugin has a Vol2 equivalent, m3mx silently retries under Vol2.
- **Native folder picker** — Output Directory uses zenity / kdialog / Tkinter in fallback order to spawn the OS file chooser.

---

## Architecture

```
                ┌────────────────────────────────────────────────────┐
                │                  Browser (SPA)                     │
                │  index.html + style.css + app.js   (boot, nav,     │
                │   manual analysis, full analysis SSE, AI chat,     │
                │   file extractor, automation, settings)            │
                └───────────────┬────────────────────────────────────┘
                                │  fetch + SSE
                                ▼
                ┌────────────────────────────────────────────────────┐
                │                Flask backend (app/)                │
                │ ┌───────────┐ ┌──────────┐ ┌───────────────────┐  │
                │ │ main.py   │ │ config.py│ │ plugins.py (178)  │  │
                │ │ /api/…    │ │ settings │ │ name resolution   │  │
                │ └───────────┘ └──────────┘ └───────────────────┘  │
                │ ┌───────────────────────┐ ┌─────────────────────┐ │
                │ │ forensics.py          │ │ agent.py            │ │
                │ │ Vol3/Vol2 wrappers,   │ │ Tool surface,       │ │
                │ │ profile auto-detect,  │ │ provider streams,   │ │
                │ │ partial-dump support  │ │ ReAct loop          │ │
                │ └───────────────────────┘ └─────────────────────┘ │
                │ ┌───────────────────────┐ ┌─────────────────────┐ │
                │ │ full_analysis.py      │ │ attack_story.py     │ │
                │ │ rule engine, findings │ │ LLM synthesis       │ │
                │ └───────────────────────┘ └─────────────────────┘ │
                │ ┌───────────────────────┐ ┌─────────────────────┐ │
                │ │ file_extractor.py     │ │ reports.py          │ │
                │ │ windows.filescan +    │ │ markdown / docx /   │ │
                │ │ dumpfiles wrappers    │ │ pdf (weasyprint)    │ │
                │ └───────────────────────┘ └─────────────────────┘ │
                └───────────────┬────────────────────────────────────┘
                                │  subprocess
                                ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Volatility 3     │    │ Volatility 2    │
                       │ /usr/local/bin/  │    │ python2 vol.py  │
                       │ vol              │    │  (auto profile) │
                       └──────────────────┘    └─────────────────┘
```

---

## Quick start (Docker — recommended)

The Docker image bundles every runtime dependency — Python 3, Python 2 (for Vol2), Volatility 3, the entire Volatility 2 source tree in `bin/volatility2/`, YARA, WeasyPrint with the right pydyf pin, ExifTool, and the DejaVu font set required by the PDF renderer. **No host install of Volatility, Python 2, or YARA is required.**

```bash
git clone <your-fork> m3mx
cd m3mx
docker compose up -d --build
```

Open <http://127.0.0.1:5000>. By default the container binds the loopback interface only — see [Security notes](#security-notes) before changing that.

**Bundled binaries**

- `bin/vol`  — thin shim around the pip-installed `volatility3` package.
- `bin/vol2` — bash wrapper that dispatches `bin/volatility2/vol.py` under `python2`.
- `bin/volatility2/` — full Vol2 source tree (≈ 34 MB, vendored from the Volatility Foundation upstream).

`config.json` ships pointing at `/app/bin/vol` and `/app/bin/vol2` so the container resolves them out of the box. Override at any time with `VOL3_PATH` / `VOL2_PATH` environment variables or via Settings in the UI.

**Persistent volumes** (bind-mounted by `docker-compose.yml`):

| Host                  | Container       | Purpose                            |
| --------------------- | --------------- | ---------------------------------- |
| `./uploads`           | `/app/uploads`  | Memory images you upload           |
| `./outputs`           | `/app/outputs`  | Plugin results + cases + reports   |
| `./config.json`       | `/app/config.json` | Settings (rw — changes persist) |
| `./rules`             | `/app/rules`    | YAML detection rules + YARA (ro)   |

**Container ops**

```bash
docker compose logs -f m3mx        # tail logs
docker compose exec m3mx /app/bin/vol --help    # poke Vol3
docker compose exec m3mx /app/bin/vol2 --info   # list Vol2 plugins
docker compose down                # stop and remove
```

---

## Quick start (native)

If you'd rather skip Docker:

| Component                          | Why                                          | Install (Debian/Kali)                                                |
| ---------------------------------- | -------------------------------------------- | -------------------------------------------------------------------- |
| Python ≥ 3.10                      | Runtime                                       | `sudo apt install python3 python3-pip python3-venv`                   |
| Volatility 3                       | Primary engine                                | `pip install volatility3`                                             |
| Volatility 2 (optional)            | Fallback for plugins missing in v3            | Use `bin/volatility2/vol.py` shipped in this repo + `python2`         |
| WeasyPrint deps (optional, for PDF)| Report renderer                               | `sudo apt install libcairo2 libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu` |
| `zenity` (optional)                | Native folder picker                          | `sudo apt install zenity`                                             |
| `yara` (optional)                  | YARA scanning                                 | `sudo apt install yara`                                               |

```bash
python3 start.py
```

The launcher:

1. Verifies Python ≥ 3.9
2. Auto-installs missing Python packages from `requirements.txt`
3. Resolves Vol2 / Vol3 paths (config first, then `$PATH`, then `bin/`)
4. Starts Flask on `http://127.0.0.1:5000`
5. Opens your default browser

### First image

1. Click the **Upload** drop-zone on Home and pick a `.raw` / `.mem` / `.dmp` / `.vmem` / `.bin`.
2. Open **Full Analysis** → **Start Full Analysis** for an end-to-end run.
3. Or open **Manual Analysis** → search a plugin → **Run**.
4. Open **AI Agent** and ask: *"Find any suspicious external connections and the parent processes that opened them."*
5. When you want the printable bundle: *"Generate a report."*

---

## Configuration

`config.json` ships with empty API keys and points at the bundled binaries. Edit it from the UI (**Settings**) or directly — changes persist via the docker-compose bind mount.

```jsonc
{
  "ai": {
    "provider": "ollama",                // openai | anthropic | google | glm | agentrouter | ollama
    "model": "",
    "api_keys": {
      "openai": "", "anthropic": "", "google": "",
      "glm": "", "agentrouter": "",
      "abuseipdb": "", "virustotal": ""
    },
    "glm_base_url":         "https://open.bigmodel.cn/api/paas/v4/",
    "agentrouter_base_url": "https://agentrouter.org/v1",
    "ollama_url":           "http://host.docker.internal:11434",
    "max_tokens": 2000,
    "temperature": 0.2,
    "allow_shell_commands": true,
    "shell_command_timeout": 300,
    "shell_workdir": ""
  },
  "volatility": {
    "vol3_path":  "/app/bin/vol",
    "vol2_path":  "/app/bin/vol2",
    "preference": "auto",                // auto (v3 → v2 fallback) | v3 | v2
    "timeout_seconds": 600
  },
  "output": {
    "directory": "/app/outputs",
    "auto_save": true,
    "formats": ["txt", "json", "csv"]
  },
  "appearance": { "theme": "dark", "language": "en", "font_size": 14 },
  "features": {
    "FULL_ANALYSIS_V2":                  true,
    "FULL_ANALYSIS_LEGACY_V1":           false,
    "FULL_ANALYSIS_OPTIONAL_AI_REPORT":  false
  }
}
```

### Environment variables

Every env var in `.env.example` overrides the corresponding `config.json` field. Useful for not committing keys.

| Variable                                | Field overridden                                    |
| --------------------------------------- | --------------------------------------------------- |
| `OPENAI_API_KEY`                        | `ai.api_keys.openai`                                |
| `ANTHROPIC_API_KEY`                     | `ai.api_keys.anthropic`                             |
| `GOOGLE_API_KEY`                        | `ai.api_keys.google`                                |
| `GLM_API_KEY`                           | `ai.api_keys.glm`                                   |
| `AGENTROUTER_API_KEY`                   | `ai.api_keys.agentrouter`                           |
| `ABUSEIPDB_API_KEY`                     | `ai.api_keys.abuseipdb`                             |
| `VT_API_KEY`                            | `ai.api_keys.virustotal`                            |
| `VOL2_PATH` / `VOL3_PATH`               | `volatility.vol2_path` / `volatility.vol3_path`     |
| `FULL_ANALYSIS_V2`                      | `features.FULL_ANALYSIS_V2`                         |
| `FULL_ANALYSIS_LEGACY_V1`               | `features.FULL_ANALYSIS_LEGACY_V1`                  |
| `FULL_ANALYSIS_OPTIONAL_AI_REPORT`      | `features.FULL_ANALYSIS_OPTIONAL_AI_REPORT`         |
| `VOL3_ALLOW_PARTIAL_DUMP`               | Vol3 partial-dump support (default `1`, already set in Dockerfile) |

### Plugin registry

`plugins.json` lists **178 plugins across 11 categories**: Processes (19), Memory (15), Network (5), Registry (12), Files (8), Malware (31), Credentials (5), System (11), Shell (2), Linux (47), macOS (23). Each entry maps a short name (`pslist`) to its Vol3 dotted name (`windows.pslist.PsList`) and its Vol2 plugin name. The runner picks Vol3 when available and silently falls back to Vol2 when Vol3's layer-stacker rejects the image. Plugins without a Vol2 mapping (e.g. `windows.vadyarascan`) just fail clean; plugins without a Vol3 mapping (a few Vol2-only community plugins) go straight to Vol2.

API keys are masked when read back via `/api/settings` (e.g. `sk-A…HTsw`). The frontend never displays them in plaintext after save.

---

## Security notes

M3MX is built for a **single trusted analyst on their own workstation**. It is not hardened for multi-tenant or public exposure.

- **No authentication.** Anything that can reach the port can use every API including the agent's shell tool. The shipped `docker-compose.yml` binds `127.0.0.1:5000` only — do not change this to `0.0.0.0` without putting an auth reverse proxy in front.
- **The agent can execute shell commands** (`run_shell` tool) when `ai.allow_shell_commands` is true (default). A denylist in `app/agent.py` rejects clearly destructive patterns (`rm -rf /`, `dd of=/dev/sdX`, fork bombs, `kill -9 1`, `iptables -F`, `wget … | sh`, etc.) but the denylist is best-effort, not a sandbox. Toggle the flag off in Settings if you don't want this.
- **Every shell invocation — allowed or rejected — is logged** to `outputs/agent_security.log` for audit.
- **The agent can read any file** the container process can read (`read_file` tool, capped at 512 KiB / call). Inside Docker this is scoped to the container's view of the filesystem.
- **Outputs are world-readable on the host** — the bind-mount preserves whatever umask the container writes with. Don't expose `outputs/` over a shared filesystem without thinking through who else sees those PIDs / credentials / memory dumps.
- **API keys live in `config.json`** in cleartext (masked when returned via `/api/settings`). The `.env.example` route is preferable for production-grade secret handling; both are gitignored.
- **Memory images are sensitive.** `uploads/` and `outputs/` are gitignored by default — never commit a real memory dump.

If you need to expose M3MX to a team, put an authenticating reverse proxy (Caddy, nginx + basic auth, Tailscale Funnel, etc.) in front and lock down the bind.

---

## Workflow walkthrough

### Full Analysis (one-click triage)

1. POST `/api/full-analysis` (no body — server uses the loaded image).
2. SSE stream emits, in order:
   - `start` → `plugin_start` × N → `plugin_done` × N → `finding` × M → `rules_done` → `saved`
   - `story_start` → `story_token` × T → `story_done` → `story_saved` → `all_done`
3. UI renders a live terminal log, ticks stat cards (`plugins`, `findings`, `critical`, `high`, `elapsed`), streams the markdown attack story, and fills the findings table with severity/MITRE/conf pills.

### Manual Analysis

1. `/api/plugins` populates the searchable plugin list (V2/V3/N/A pills).
2. POST `/api/run-plugin {plugin, version, params, extra_params}` runs it.
3. Tabular CSV output is rendered chunked (handles 50 k+ row plugins). Free-form `extra_params` (e.g. `--pid 1234`) are forwarded verbatim.
4. Highlight search with ↑ / ↓ navigation. Export CSV / JSON / TXT. Copy.

### Automation Workflows

Pre-built playbooks chain plugins → end with an **AI synthesis** step that ingests the prior plugin outputs as JSON and produces an executive summary. **The AI step never invokes new tools** — the prompt explicitly forbids it, and the SSE consumer ignores any rogue `tool_call` events client-side. Results land in a modal + execution-history list.

### File Extractor

`windows.filescan` → tree → click a file → metadata + hex + strings tabs (lazy-loaded via `/api/files/preview`). Multi-select extract via `/api/files/extract` writes to `outputs/extracted/`.

### AI Agent

`/api/agent/chat` (SSE) drives a ReAct loop (8 rounds). The model decides which tool to call; tool calls and results render as cards inside the bot bubble. Markdown formatting, MITRE links, and finding-id chips render inline.

---

## The AI agent

### Tools available

| Tool              | Purpose                                                      |
| ----------------- | ------------------------------------------------------------ |
| `run_volatility`  | Run any plugin in `plugins.json` (v2/v3 auto)                |
| `run_shell`       | Arbitrary shell command (denylist for `rm -rf /`, `dd of=/dev`, fork bombs, …) |
| `read_file`       | Read any file on the workstation, ≤ 512 KiB per call         |
| `list_outputs`    | Enumerate `outputs/`                                         |
| `read_output`     | Read a saved plugin output                                   |
| `web_search`      | DuckDuckGo HTML — no key required                            |
| `threat_intel`    | AbuseIPDB (IPs) / VirusTotal (hashes & domains)              |
| `yara_scan`       | Wraps `windows.vadyarascan` with `rules/malware_rules.yar`   |
| `generate_report` | **On-demand only** — renders the case to PDF                 |

### Persona

The system prompt is the editable Dual-Mode prompt in `app/agent.py` — chat naturally for general questions, drop into autonomous Hunt Mode for forensic investigations.

### Safety

- A denylist in `agent.py` rejects clearly destructive commands; everything else runs.
- Every shell invocation (allowed or rejected) is appended to `outputs/agent_security.log`.
- `generate_report` is gated — the prompt forbids autonomous invocation.

---

## API reference

| Method | Path                                  | Purpose                                              |
| ------ | ------------------------------------- | ---------------------------------------------------- |
| GET    | `/api/health`                         | Readiness probe                                      |
| GET    | `/api/settings`                       | Read config (keys masked)                            |
| POST   | `/api/settings`                       | Persist config (merges deeply)                       |
| GET    | `/api/loaded-image`                   | Restore session image after refresh                  |
| POST   | `/api/upload`                         | Streamed image upload (multipart)                    |
| GET    | `/api/plugins`                        | Plugin registry annotated with availability          |
| POST   | `/api/run-plugin`                     | Run one plugin synchronously                         |
| POST   | `/api/run-plugin/stream`              | SSE — stream plugin stdout/stderr live               |
| POST   | `/api/agent/chat`                     | SSE — ReAct chat                                     |
| POST   | `/api/agent/test`                     | Provider liveness check                              |
| POST   | `/api/agent/reset`                    | Clear chat history on disk                           |
| GET    | `/api/agent/history`                  | Read saved chat history                              |
| POST   | `/api/full-analysis`                  | SSE — V2 triage pipeline + attack story              |
| GET    | `/api/full-analysis/case`             | Reload a saved case (findings + story)               |
| POST   | `/api/full-analysis/ai-report`        | SSE — generate `ai_report.md` (gated by feature flag) |
| POST   | `/api/full-analysis/export-pdf`       | Render `report.md` → PDF (deterministic, no LLM)     |
| POST   | `/api/reports/generate`               | Aggregate JSON outputs into a single report          |
| POST   | `/api/files/scan`                     | `windows.filescan` → file tree                       |
| POST   | `/api/files/preview`                  | Hex + strings + metadata for one offset              |
| POST   | `/api/files/extract`                  | Dump files for a list of offsets                     |
| GET    | `/api/files/raw?path=…`               | Stream a previously-extracted file (path-traversal guarded — must live inside `outputs/`) |
| GET    | `/api/outputs`                        | List the saved outputs directory                     |
| GET    | `/api/outputs/view?name=…`            | Read one output                                      |
| GET    | `/api/outputs/download?name=…`        | Download                                             |
| POST   | `/api/outputs/delete`                 | Remove                                               |
| POST   | `/api/triage`                         | Quick triage (parallel)                              |
| GET    | `/api/status`                         | Current job status (state + last message)            |
| GET    | `/api/fs/browse?path=…`               | List subfolders for the in-app folder picker         |
| POST   | `/api/fs/mkdir`                       | Create a directory                                   |
| POST   | `/api/fs/pick-dir-native`             | Open the native OS folder picker (zenity / Tk)       |
| GET    | `/api/ollama/models`                  | List models from a running Ollama daemon             |

All POSTs accept JSON unless noted. SSE endpoints emit `data: <json>\n\n` events.

---

## Project layout

```
M3MX/
├── Dockerfile                # python:3.12-slim-bullseye + py2 + Vol3 + yara + weasyprint
├── docker-compose.yml        # single-service stack, binds 127.0.0.1:5000
├── start.py                  # Native launcher — installs deps, detects Vol, opens browser
├── config.json               # Persisted settings (auto-merged with DEFAULT_CONFIG)
├── plugins.json              # 178-entry registry — name resolution + v2/v3 mapping
├── requirements.txt
├── .env.example              # Env-var overrides (gitignore your real .env)
├── bin/
│   ├── vol                   # Vol3 launcher (python shim around pip-installed volatility3)
│   ├── vol2                  # Vol2 launcher (bash → python2 → bin/volatility2/vol.py)
│   └── volatility2/          # Bundled Vol2 source tree (~34 MB)
├── app/
│   ├── main.py               # Flask app factory + every /api/* route
│   ├── config.py             # DEFAULT_CONFIG + load/save/mask + feature flags
│   ├── plugins.py            # Registry loader + flexible name resolver
│   ├── forensics.py          # Vol2/Vol3 subprocess wrappers + auto-profile + fallback
│   ├── agent.py              # LLM tool surface, providers, ReAct loop, shell denylist
│   ├── full_analysis.py      # V2 dispatcher (run_triage) + case directory layout
│   ├── attack_story.py       # AI narrative generator (post-triage)
│   ├── file_extractor.py     # filescan + dumpfiles wrappers + preview/extract/raw
│   ├── reports.py            # Aggregated report rendering
│   └── fa2/                  # Full Analysis V2 — 10-stage pipeline
│       ├── os_detect.py        →  banners / windows.info → OS + arch
│       ├── plugin_planner.py   →  per-OS plugin lists from rules/plugin_plans.yaml
│       ├── volatility_runner.py→  parallel plugin executor with retry/fallback
│       ├── normalizers/        →  raw plugin → Artifact{} per OS
│       ├── rule_engine.py      →  YAML rules → Finding{} with severity/confidence
│       ├── mitre.py            →  Tactic/Technique tagging via rule.tags
│       ├── correlation.py      →  multi-rule chains
│       ├── timeline.py         →  ordered finding timeline
│       ├── report.py           →  Markdown → HTML → PDF (WeasyPrint)
│       └── ai_report.py        →  Optional, gated AI narrative
├── static/
│   ├── css/style.css         # Single dark theme (M3MX CORTEX)
│   ├── js/app.js             # SPA — boot, nav, all SSE consumers, 4 playbooks
│   └── assets/
├── templates/
│   └── index.html            # Single-page shell (boot → app)
├── rules/
│   ├── plugin_plans.yaml     # Per-OS Vol3 plugin lists used by the V2 planner
│   ├── common_rules.yaml     # Cross-OS detection rules
│   ├── windows_rules.yaml    # Windows-specific rules
│   ├── linux_rules.yaml      # Linux-specific rules
│   ├── mac_rules.yaml        # macOS-specific rules
│   └── baseline.yaml         # Allowlists (browser TLS to public IPs, etc.)
├── outputs/                  # ← mounted from host; case dirs + reports + logs
└── uploads/                  # ← mounted from host; memory images live here
```

---

## Troubleshooting

| Symptom                                                                                 | Most likely cause / fix                                                                                                                              |
| --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Unsatisfied requirement plugins.X.kernel.layer_name` on Vol3                           | Partial / truncated dump. m3mx auto-falls back to Vol2 for plugins that have a v2 mapping. Set `VOL3_ALLOW_PARTIAL_DUMP=1` (the launcher does this).  |
| `No suitable address space mapping found` on Vol2                                       | Profile not detected. m3mx now auto-runs `imageinfo` and caches the profile — restart the server once if you upgraded mid-session.                  |
| `pstree` returns 0 rows but `psscan` works                                              | Image is missing paged kernel structures. Use `psscan` (pool-tag scan) — m3mx prefers it on small dumps.                                              |
| `401 invalid x-api-key` for Anthropic                                                   | Real Anthropic keys start with `sk-ant-`. If yours starts with `sk-…` it's a third-party proxy — set provider to `agentrouter` (or add a custom one). |
| Gemini returns `429 limit: 0`                                                           | The free tier has no quota for `gemini-2.5-pro`. Use `gemini-2.5-flash` or `gemini-2.5-flash-lite` until billing is enabled.                          |
| WeasyPrint missing libraries                                                            | `sudo apt install libcairo2 libpango-1.0-0 libpangoft2-1.0-0 libffi-dev libgdk-pixbuf2.0-0`                                                            |
| Native folder picker doesn't appear                                                     | Install `zenity` or `kdialog`; m3mx falls back to a web modal otherwise.                                                                              |

---

## Known limitations

- **No authentication** of any kind — see [Security notes](#security-notes).
- **Single-user** by design — there is no per-user state, locking, or queueing. Concurrent uploads or analyses against the same image will collide.
- **Vol2 imageinfo is the canonical profile source** — if `imageinfo` fails on a corrupt header, Vol2 plugins won't work even though Vol2 itself is healthy. Vol3 plugins are unaffected.
- **The agent is greedy with tokens** — `max_tokens` is per response; the 8-round ReAct loop can run multiple round-trips. Set provider limits if you care about cost.
- **PDF reports require a fully-cached case** — `/api/full-analysis/export-pdf` reads `report.md` from disk; it will refuse with HTTP 412 if Full Analysis hasn't been run for the image yet.

---

## Contributing & License

Issues and PRs welcome. The codebase is intentionally small and self-contained — every backend file is documented with a header explaining the public API.

Released under the **MIT License**. See [`LICENSE`](LICENSE).

The bundled `bin/volatility2/` directory is a verbatim vendor of the Volatility Foundation's Volatility 2 codebase, used under the **Volatility Software License (VSL)** — see `bin/volatility2/LICENSE.txt`. Volatility 3 is installed at container build time via pip from the same project under the same terms.

> Built on top of the [Volatility Foundation](https://www.volatilityfoundation.org)'s open-source framework. m3mx is a wrapper, not a fork. All credit for the underlying memory-analysis engine belongs to the Volatility maintainers.
