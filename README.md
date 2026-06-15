<div align="center">

# M3MX

### Unified Autonomous Memory Forensics Workbench

**Orchestrate Volatility. Guided by Intelligence.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-black)](https://flask.palletsprojects.com/)
[![Volatility](https://img.shields.io/badge/Volatility-2%20%26%203-orange)](https://www.volatilityfoundation.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)

[Website](https://www.m3mx.xyz/) • [Features](#-features) • [Quick Start](#-quick-start) • [API](#-api-reference) • [Architecture](#-architecture)

</div>

---

##  Overview

**M3MX** is a Flask-based memory forensics workbench that wraps **Volatility 3** (with **Volatility 2** fallback) behind a clean, browser-based UI. It enables analysts to upload a memory image, run manual or automated forensic plugins, extract memory-resident files, generate findings, map adversary behavior to **MITRE ATT&CK**, build correlated timelines, and optionally bring an **AI agent** into the investigation loop for chat-driven analysis and reporting.

> 🎓 This project was developed as a **graduation project** for the Computer Science program at Tafila Technical University. Check out the project website at **[m3mx.xyz](https://www.m3mx.xyz/)**.

> ⚠️ **Designed for local use.** M3MX ships with **no authentication**. It is intended to run on `127.0.0.1` for personal/lab use — see [Security Notes](#-security-notes) before exposing it to a network.

---

##  Features

###  V2 Full Analysis Pipeline
A single click detects the target OS, plans the optimal plugin set, executes Volatility in parallel, normalizes raw output into structured artifacts, evaluates YAML-based detection rules, scores findings, maps them to MITRE ATT&CK, correlates related events, and builds a deterministic timeline + report — all in **10 deterministic stages**.

| Stage | Description |
|-------|-------------|
| 01 — OS Detection | Identifies kernel/profile from the memory image |
| 02 — Plugin Planning | Selects relevant plugins based on OS |
| 03 — Volatility Run | Executes plugins via parallelized subprocess streams |
| 04 — Normalization | Converts raw rows into unified artifact types |
| 05 — Rule Engine | Applies YAML detection rules & baselines |
| 06 — Scoring | Maps findings to info/low/medium/high/critical |
| 07 — MITRE Mapping | Correlates behavior to ATT&CK techniques |
| 08 — Correlation | Links related PIDs, sockets, VAD nodes, etc. |
| 09 — Timeline Build | Orders confirmed events chronologically |
| 10 — Report Generation | Produces Markdown, PDF (WeasyPrint), and DOCX reports |

###  AI Forensic Agent
A chat-driven copilot (`/api/agent/chat`) that supports **OpenAI, Anthropic, Google Gemini, GLM/Zhipu, AgentRouter, and Ollama**. The agent can:
- Run Volatility plugins on demand
- Execute shell commands (with destructive-pattern denylisting + logging)
- Read and list output files
- Perform web/OSINT and threat-intel lookups
- Persist chat history across sessions

### 🗂️ Interactive File Extractor
Runs `filescan`, classifies high-value files, and extracts them by offset via `windows.dumpfiles.DumpFiles` (Vol3) or `dumpfiles` (Vol2) — with inline hex/strings/MIME/EXIF previews.

### 🛠️ Manual Plugin Runner
Direct access to **178 registered Volatility plugins** spanning Processes, Memory, Network, Registry, Files, Malware, Credentials, System, Shell, Linux, and macOS — with live streaming output (SSE) and sortable CSV result tables.

### 🚦 Quick Triage
Runs a curated essential plugin set in parallel: `imageinfo`, `pslist`, `pstree`, `psscan`, `cmdline`, `netscan`, `malfind`, `svcscan`, `filescan`, `hashdump`.

### 📄 Reporting
Generates Markdown, PDF, and DOCX reports from saved plugin output, including an optional LLM-generated **"Attack Story"** narrative.

---

##  Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3, Flask, Flask-CORS |
| Forensics Engines | Volatility 3 (primary), Volatility 2 (fallback) |
| Frontend | Server-rendered templates + vanilla JS (`static/js/app.js`) |
| Config & Rules | JSON config, `plugins.json`, YAML rule packs & baselines |
| AI Providers | OpenAI, Anthropic, Google Gemini, GLM/Zhipu, AgentRouter, Ollama |
| Reporting | ReportLab, WeasyPrint, python-docx, Markdown → HTML/PDF |
| Containerization | Docker / Docker Compose |

---

##  Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/0x3xP01t3r/M3MX.git
cd m3mx-tool
docker compose up -d --build
```

Then open your browser at:

```
http://127.0.0.1:5000
```

#### Docker Volumes

| Host Path | Container Path | Purpose |
|---|---|---|
| `./uploads` | `/app/uploads` | Uploaded memory images |
| `./outputs` | `/app/outputs` | Plugin outputs, cases, reports, logs |
| `./config.json` | `/app/config.json` | App configuration |
| `./rules` | `/app/rules` (read-only) | YAML rule packs & baselines |

> 🍏 **Apple Silicon (M1/M2/M3/M4) users** — see the [Apple Silicon / ARM64 Dockerfile note](#-apple-silicon-arm64-notes) below before building.

---

### Native Setup

> ⚠️ Native setup is designed and tested for **Debian-based distributions**. Other distros may work but are not officially supported.

```bash
sudo apt install python3 python3-pip python3-venv
pip install -r requirements.txt
pip install volatility3
python3 start.py
```

#### Optional Native Components

```bash
sudo apt install python2 yara exiftool libcairo2 libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu zenity
```

> ℹ️ `start.py` binds to `0.0.0.0` by default, exposing the app on **all network interfaces**. Restrict this if running on a shared network.

---

## 🍏 Apple Silicon / ARM64 Notes

If you're building the Docker image on **Apple Silicon (M1/M2/M3/M4)**, some `x86_64`-only packages (notably `zlib1g-dev`, `libjpeg-dev`, `libfreetype6-dev` build chains) require additional dev headers to compile cleanly under emulation/ARM64. Update the system dependency layer in the `Dockerfile` as follows:

**For Apple Silicon (ARM64):**

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
        python2 python2-dev \
        yara \
        exiftool \
        libcairo2 libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf-2.0-0 \
        shared-mime-info libffi-dev libssl-dev \
        zlib1g-dev libjpeg-dev libfreetype6-dev \
        fonts-dejavu fonts-dejavu-core \
        build-essential \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
```

**For standard x86_64 systems:**

```dockerfile
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
```

Replace the corresponding `RUN apt-get install` block in your `Dockerfile` with the version matching your architecture before running `docker compose up -d --build`.

---

##  API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `GET/POST` | `/api/settings` | Get/update app configuration |
| `POST` | `/api/upload` | Upload a memory image (chunked) |
| `GET` | `/api/plugins` | List registered Volatility plugins |
| `POST` | `/api/run-plugin` | Run a single plugin |
| `POST` | `/api/run-plugin/stream` | Stream plugin execution (SSE) |
| `POST` | `/api/triage` | Run quick triage plugin set |
| `POST` | `/api/full-analysis` | Run Full Analysis V1/V2 pipeline |
| `GET` | `/api/full-analysis/case` | Retrieve Full Analysis case data |
| `POST` | `/api/full-analysis/ai-report` | Generate AI-narrated report |
| `POST` | `/api/full-analysis/export-pdf` | Export Full Analysis report as PDF |
| `POST` | `/api/files/scan` | Run filescan |
| `POST` | `/api/files/preview` | Preview file by offset (hex/strings/EXIF) |
| `POST` | `/api/files/extract` | Extract file from memory image |
| `GET` | `/api/files/raw` | Serve raw extracted file |
| `GET` | `/api/outputs` | List saved outputs |
| `GET` | `/api/outputs/view` | View an output file |
| `GET` | `/api/outputs/download` | Download an output file |
| `POST` | `/api/outputs/delete` | Delete an output file |
| `POST` | `/api/reports/generate` | Generate Markdown/PDF/DOCX report |
| `POST` | `/api/agent/chat` | Chat with the AI forensic agent |
| `GET` | `/api/agent/history` | Get agent chat history |
| `POST` | `/api/agent/test` | Test AI provider connection |
| `POST` | `/api/agent/reset` | Reset agent chat history |

---

##  Architecture

M3MX is built as a local Flask-based web application.

**High-level flow:**

```
User Browser
    |
    v
M3MX Web Interface
    |
    v
Flask Backend
    |
    +--> Volatility 3
    |
    +--> Volatility 2
    |
    +--> Rule Engine
    |
    +--> File Extractor
    |
    +--> Report Generator
    |
    +--> Optional AI Agent
    |
    v
uploads/ and outputs/
```

**Typical analysis flow:**

1. Upload memory image
2. Select analysis mode
3. Backend runs Volatility plugins
4. Results are parsed and normalized
5. Detection rules are applied
6. Findings are scored
7. Timeline and correlations are generated
8. Reports and exports are created
9. Analyst reviews evidence from the GUI

### App Pages

| Page | Description |
|---|---|
| 🏠 **Home** | Upload a memory image and view loaded image status |
| 🔎 **Full Analysis** | Run the automated 10-stage detection pipeline (OS detection → report generation) |
| 🛠️ **Manual Analysis** | Run individual Volatility plugins with live streamed output |
| ⚙️ **Automation Workflows** | Chain plugins/playbooks into repeatable automated workflows |
| 🤖 **AI Agent** | Chat-based investigation assistant with tool-calling capabilities |
| 🗂️ **File Extractor** | Scan, preview, and extract files directly from the memory image |
| ⚙️ **Settings** | Configure Volatility paths, output directory, and AI provider **API keys** |

> 🔑 **Note:** The AI Agent and AI-generated reports require an **API key** from a supported provider (OpenAI, Anthropic, Google Gemini, GLM/Zhipu, AgentRouter) or a local **Ollama** instance. Configure these under **Settings**.

---

##  Security Notes

- **No built-in authentication** — do not expose M3MX directly to the internet.
- Docker binds to `127.0.0.1:5000` by default (loopback only).
- Native `start.py` binds to `0.0.0.0` by default — change this for restricted environments.
- The AI agent can execute shell commands (`ai.allow_shell_commands: true` by default). Destructive command patterns are denied, and all shell attempts are logged to `outputs/agent_security.log`.
- Output file serving enforces path resolution checks to prevent directory traversal.

---

##  Contributing

Contributions, issues, and feature requests are welcome. Feel free to check the [issues page](https://github.com/0x3xP01t3r/M3MX/issues).

---

##  License

This project is released under the [MIT License](LICENSE).

---

## 🎓 Acknowledgments

M3MX is a **graduation (capstone) project** developed at **Tafila Technical University**, Department of Computer Science.

A huge thanks to my teammates for their effort and dedication throughout this project — this wouldn't have been possible without the great teamwork.

Special thanks to our supervisor, **Dr. Ibrahim Altarawneh**, for his continuous guidance and support throughout the development of this project.

---

<div align="center">

Built for analysts who need clean, containerized, autonomous memory forensics.

🌐 [m3mx.xyz](https://www.m3mx.xyz/)

</div>
