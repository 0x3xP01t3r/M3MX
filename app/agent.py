"""
m3mx tool — AI agent engine.

Provides a provider-agnostic streaming chat interface that can call a
flexible set of forensics tools on the host system:

    run_volatility(plugin, version="auto")
    run_shell(command, timeout=120)
    read_file(path, max_bytes=65536, offset=0)
    list_outputs()
    read_output(filename, max_bytes=20000)

SECURITY MODEL
==============
The agent CAN run shell commands when ``ai.allow_shell_commands`` is
true in config.json (default: true, since this tool is meant to be an
analyst's workstation assistant). Every shell invocation — whether
allowed or rejected — is appended to outputs/agent_security.log so an
auditor can review what the model asked for.

Commands matching a denylist of clearly destructive operations
(``rm -rf /``, ``dd of=/dev/sdX``, ``mkfs``, forkbombs, shutdown/reboot,
etc.) are rejected unconditionally. Shell commands are run with the
working directory pinned to the uploads/ folder by default so the
model can analyze the memory image it was given without fighting paths.

STREAMING
=========
The ``stream_chat`` generator yields dict events:

    {"type": "token",     "content": "..."}       # partial text
    {"type": "tool_call", "name": "...", "args": {...}}
    {"type": "tool_result","name": "...", "result": {...}}
    {"type": "done",      "usage": {"input": n, "output": n}, "model": "..."}
    {"type": "error",     "message": "..."}
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Callable, Generator, Iterable

import requests

from .config import OUTPUTS_DIR, UPLOADS_DIR, get_api_key, load_config
from . import forensics, plugins as plugin_registry

log = logging.getLogger("m3mx.agent")
SECURITY_LOG = OUTPUTS_DIR / "agent_security.log"
HISTORY_FILE = OUTPUTS_DIR / "chat_history.json"

ALLOWED_COMMAND_PREFIXES = ("vol", "vol.py", "python vol.py", "python3 vol.py")

# Patterns that are NEVER allowed, even with allow_shell_commands=true.
# Shell history and backups are protected; these are the "root the box"
# or "destroy evidence" class of commands that have no place in a
# forensic investigation.
DANGEROUS_PATTERNS: list[tuple[str, str]] = [
    (r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\s+--force|--force\s+--recursive|-rf|-fr)\s+/\s*($|;|&|\|)",
        "rm -rf /"),
    (r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-rf|-fr)\s+(/bin|/boot|/dev|/etc|/home|/lib|/proc|/root|/sbin|/sys|/usr|/var)(\s|/|$)",
        "rm -rf on system directory"),
    (r"\bdd\s+[^|&;]*\bof\s*=\s*/dev/(sd|nvme|hd|xvd|vd|mmcblk)",
        "dd to block device"),
    (r"\bmkfs(\.[a-z0-9]+)?\s+/dev/",
        "mkfs on a device"),
    (r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
        "fork bomb"),
    (r"\b(shutdown|reboot|halt|poweroff)\b(\s|$)",
        "system power command"),
    (r"\bkill\s+-9?\s+1\b",
        "kill init (pid 1)"),
    (r"\bchmod\s+-R\s+0*0*0\s+/\s*($|;|&)",
        "chmod 000 /"),
    (r">\s*/dev/(sd|nvme|hd|xvd|mmcblk)",
        "overwrite a block device"),
    (r"\biptables\s+-F\b",
        "flush firewall"),
    (r"\b(wget|curl)[^|&;]*\|\s*(sh|bash|zsh)\b",
        "pipe remote content into shell"),
]
_DANGEROUS_RE = [(re.compile(pat, re.IGNORECASE), reason)
                 for pat, reason in DANGEROUS_PATTERNS]


def _security_event(verdict: str, cmd: str, detail: str = "") -> None:
    SECURITY_LOG.parent.mkdir(exist_ok=True, parents=True)
    line = (f"{datetime.datetime.utcnow().isoformat()}Z  {verdict:<7}  "
            f"{detail}  :: {cmd!r}\n")
    with open(SECURITY_LOG, "a", encoding="utf-8") as f:
        f.write(line)


SYSTEM_PROMPT_TEMPLATE = """\
**Role & Persona:**
You are the core AI Assistant integrated into "m3mx tool", an advanced memory forensics platform.
You possess a "Dual-Mode" personality. You are highly intelligent, flexible, and natural to converse with, but you are also an elite DFIR investigator when needed. NEVER output walls of text apologizing.

**Operating Mode 1: The General Assistant (Default)**
- When the user asks general questions, wants to brainstorm, or asks for basic OS-level tasks (e.g., "create a folder", "list directory contents", "write a python script"), act as a natural, helpful AI.
- Use your `run_shell` tool flexibly to perform operating system tasks (like `mkdir`, `ls`, or `cat`) directly if requested.
- Keep your conversational tone normal, professional, and concise.

**Operating Mode 2: The DFIR Investigator (Triggered on Analysis Requests)**
- When the user commands a forensic investigation (e.g., "Analyze this dump", "Find hidden processes", "Dump the flag.txt", "Scan with YARA"), instantly drop the conversational tone and enter Hunt Mode.
- **Zero-Shot ReAct Loop:** Do not ask for permission. Formulate a plan silently and execute your Volatility MCP tools immediately.
- **Relentless Execution:** If a Volatility tool fails (e.g., missing parameter), read the error, correct your JSON, and retry silently. Do not bother the user with failure logs.
- **File Extraction:** If asked to dump a file, use `windows.dumpfiles` (or the appropriate Vol3 equivalent) and ensure you use the `dump_dir` parameter to save it to the workspace.

**Context Rule:**
Assume the memory image path is always correctly managed by the backend. Never complain about "No memory image loaded". If a path issue occurs, assume it's a backend sync delay and ask the user to quickly refresh the context.

**Prime Directive:**
Be natural when chatting, execute general IT tasks effortlessly via shell, but become an aggressive, autonomous DFIR hound when investigating memory.
"""


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

def is_command_dangerous(cmd: str) -> tuple[bool, str]:
    """Return (True, reason) if command matches the denylist, else (False, '')."""
    if not isinstance(cmd, str) or not cmd.strip():
        return False, ""
    for regex, label in _DANGEROUS_RE:
        if regex.search(cmd):
            return True, label
    return False, ""


def log_security_violation(cmd: str, reason: str) -> None:
    """Record a rejected command/attempt. Kept for backwards compatibility."""
    _security_event("REJECT", cmd, reason)
    log.warning("Agent security violation: %s — %s", reason, cmd)


# ---------------------------------------------------------------------------
# Tool definitions (what we expose to the LLM)
# ---------------------------------------------------------------------------

TOOL_SCHEMAS = [
    {
        "name": "run_volatility",
        "description": "Run a Volatility plugin against the loaded memory image. "
                       "Plugin name must match the m3mx registry (e.g. pslist, malfind, netscan).",
        "parameters": {
            "type": "object",
            "properties": {
                "plugin":  {"type": "string", "description": "Short plugin name"},
                "version": {"type": "string", "enum": ["auto", "v2", "v3"], "default": "auto"},
            },
            "required": ["plugin"],
        },
    },
    {
        "name": "run_shell",
        "description": "Run an arbitrary shell command on the analyst workstation "
                       "and return stdout/stderr/exit code. Use this for forensic "
                       "tooling not covered by run_volatility: strings, file, yara, "
                       "binwalk, exiftool, foremost, sleuthkit (fls/icat/mmls), "
                       "hashing (md5sum/sha256sum), grep, xxd, objdump, python3, "
                       "pip, etc. Working directory defaults to the uploads folder.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command line"},
                "timeout": {"type": "integer", "default": 120,
                            "description": "Seconds to wait before killing the process"},
                "cwd":     {"type": "string",
                            "description": "Optional working directory override"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Read any file on the analyst workstation (with a size cap). "
                       "Use this to inspect extracted artifacts, logs, or uploads.",
        "parameters": {
            "type": "object",
            "properties": {
                "path":      {"type": "string"},
                "max_bytes": {"type": "integer", "default": 65536},
                "offset":    {"type": "integer", "default": 0},
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_outputs",
        "description": "List files currently saved in the outputs directory.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "read_output",
        "description": "Read a previously-saved output file from outputs/. "
                       "Returns at most max_bytes bytes.",
        "parameters": {
            "type": "object",
            "properties": {
                "filename":  {"type": "string"},
                "max_bytes": {"type": "integer", "default": 20000},
            },
            "required": ["filename"],
        },
    },
    {
        "name": "web_search",
        "description": "OSINT lookup via DuckDuckGo HTML. No API key required. "
                       "Use for CVE details, malware family writeups, IP/domain "
                       "context, threat-actor backgrounders. Returns top 5 hits.",
        "parameters": {
            "type": "object",
            "properties": {
                "query":     {"type": "string"},
                "max_hits":  {"type": "integer", "default": 5},
                "timeout":   {"type": "integer", "default": 12},
            },
            "required": ["query"],
        },
    },
    {
        "name": "threat_intel",
        "description": "Reputation/enrichment lookup for a single indicator "
                       "(IPv4, IPv6, MD5, SHA1, SHA256, or domain). Auto-routes "
                       "to AbuseIPDB (IPs) or VirusTotal (hashes/domains). "
                       "API keys read from config.json → ai.api_keys.{abuseipdb,virustotal}.",
        "parameters": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string"},
                "timeout":   {"type": "integer", "default": 10},
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "yara_scan",
        "description": "Run windows.vadyarascan against a YARA rules file. "
                       "Default ruleset is rules/malware_rules.yar. Optionally "
                       "scope to a single PID. Backed by the Volatility 3 plugin.",
        "parameters": {
            "type": "object",
            "properties": {
                "pid":        {"type": "integer", "description": "Limit scan to one PID"},
                "rules_file": {"type": "string",  "description": "Path to YARA rules"},
            },
        },
    },
    {
        "name": "generate_report",
        "description": "ON-DEMAND ONLY — never call this tool unless the user "
                       "explicitly asks for a PDF / report / export / printable "
                       "summary. Renders a polished PDF from a Full Analysis "
                       "case (reads findings.jsonl + attack_story.md, writes "
                       "report.pdf). If case_id is omitted, uses the loaded image.",
        "parameters": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string", "description": "Image stem (e.g. MemoryDump)"},
            },
        },
    },
]


def _tool_run_volatility(args: dict, ctx: dict) -> dict:
    plugin = args.get("plugin", "").strip()
    version = args.get("version", "auto")
    if not plugin:
        return {"error": "plugin is required"}
    if not ctx.get("image_path"):
        return {"error": "no memory image loaded"}
    result = forensics.run_plugin(
        ctx["image_path"], plugin, version=version,
        timeout=ctx.get("timeout", 600),
        vol_paths=ctx.get("vol_paths"),
    )
    d = result.to_dict()
    # Truncate huge outputs to keep token cost sane
    if d.get("output") and len(d["output"]) > 20000:
        d["output"] = d["output"][:20000] + "\n...[truncated to 20000 chars]"
    if d.get("rows") and len(d["rows"]) > 40:
        d["rows"] = d["rows"][:40]
        d["truncated_rows"] = True
    return d


def _tool_list_outputs(args: dict, ctx: dict) -> dict:
    out_dir = Path(ctx.get("output_dir") or OUTPUTS_DIR)
    if not out_dir.exists():
        return {"files": []}
    files = []
    for p in sorted(out_dir.iterdir()):
        if p.is_file():
            st = p.stat()
            files.append({
                "name": p.name, "size": st.st_size,
                "modified": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
            })
    return {"files": files}


def _tool_read_output(args: dict, ctx: dict) -> dict:
    name = args.get("filename", "")
    max_bytes = int(args.get("max_bytes", 20000))
    out_dir = Path(ctx.get("output_dir") or OUTPUTS_DIR).resolve()
    target = (out_dir / name).resolve()
    if out_dir not in target.parents and target != out_dir:
        log_security_violation(name, "read_output: path escapes output dir")
        return {"error": "path not allowed"}
    if not target.exists() or not target.is_file():
        return {"error": f"not found: {name}"}
    data = target.read_bytes()[:max_bytes]
    try:
        content = data.decode("utf-8", errors="replace")
    except Exception:
        content = repr(data)
    return {"filename": name, "content": content,
            "bytes": len(data), "truncated": target.stat().st_size > max_bytes}


# Character budget per run_shell call so one command can't flood the LLM.
_SHELL_STDOUT_BUDGET = 16000
_SHELL_STDERR_BUDGET = 4000
_READ_FILE_HARD_CAP  = 512 * 1024    # 512 KiB


def _truncate(text: str, budget: int) -> tuple[str, bool]:
    if text is None:
        return "", False
    if len(text) <= budget:
        return text, False
    kept = text[:budget]
    dropped = len(text) - budget
    return f"{kept}\n…[truncated {dropped} more chars]", True


def _tool_run_shell(args: dict, ctx: dict) -> dict:
    cmd = str(args.get("command", "")).strip()
    if not cmd:
        return {"error": "command is required"}

    cfg = load_config()
    ai_cfg = cfg.get("ai", {})
    if not ai_cfg.get("allow_shell_commands", True):
        _security_event("BLOCK", cmd, "allow_shell_commands=false in settings")
        return {"error": "shell commands are disabled in Settings → AI"}

    dangerous, reason = is_command_dangerous(cmd)
    if dangerous:
        _security_event("DENY", cmd, f"denylist: {reason}")
        return {"error": f"command denied by safety policy: {reason}"}

    # Resolve timeout and working directory.
    max_timeout = int(ai_cfg.get("shell_command_timeout", 300))
    timeout = max(1, min(int(args.get("timeout", 120) or 120), max_timeout))
    cwd_override = str(args.get("cwd") or "").strip()
    default_cwd = ai_cfg.get("shell_workdir") or str(UPLOADS_DIR)
    cwd = cwd_override or default_cwd
    if not Path(cwd).exists():
        cwd = str(UPLOADS_DIR)

    _security_event("ALLOW", cmd, f"cwd={cwd} timeout={timeout}")

    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=cwd, errors="replace",
        )
    except subprocess.TimeoutExpired as e:
        partial_out, _ = _truncate(e.stdout or "", _SHELL_STDOUT_BUDGET)
        partial_err, _ = _truncate(e.stderr or "", _SHELL_STDERR_BUDGET)
        return {"command": cmd, "cwd": cwd, "timed_out": True,
                "timeout": timeout, "stdout": partial_out, "stderr": partial_err,
                "error": f"command timed out after {timeout}s"}
    except FileNotFoundError as e:
        return {"error": f"binary not found: {e}", "command": cmd}
    except Exception as e:                                  # pragma: no cover
        log.exception("run_shell failure")
        return {"error": f"{type(e).__name__}: {e}", "command": cmd}

    stdout, stdout_trunc = _truncate(proc.stdout, _SHELL_STDOUT_BUDGET)
    stderr, stderr_trunc = _truncate(proc.stderr, _SHELL_STDERR_BUDGET)
    return {
        "command":    cmd,
        "cwd":        cwd,
        "returncode": proc.returncode,
        "stdout":     stdout,
        "stderr":     stderr,
        "truncated":  stdout_trunc or stderr_trunc,
        "timed_out":  False,
    }


def _tool_read_file(args: dict, ctx: dict) -> dict:
    raw = str(args.get("path", "")).strip()
    if not raw:
        return {"error": "path is required"}
    try:
        target = Path(raw).expanduser().resolve()
    except Exception as e:
        return {"error": f"invalid path: {e}"}
    if not target.exists():
        return {"error": f"not found: {target}"}
    if not target.is_file():
        return {"error": f"not a regular file: {target}"}

    max_bytes = max(1, min(int(args.get("max_bytes", 65536) or 65536),
                           _READ_FILE_HARD_CAP))
    offset = max(0, int(args.get("offset", 0) or 0))
    try:
        with open(target, "rb") as f:
            if offset:
                f.seek(offset)
            data = f.read(max_bytes)
    except PermissionError:
        _security_event("DENY", raw, "read_file: permission denied")
        return {"error": f"permission denied: {target}"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}

    _security_event("READ", str(target),
                    f"offset={offset} bytes={len(data)}")
    # Try utf-8, fall back to hex preview for binary content.
    try:
        content = data.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        content = data[:4096].hex()
        encoding = "hex-preview"
    size = target.stat().st_size
    return {
        "path": str(target), "size": size, "offset": offset,
        "bytes_read": len(data), "encoding": encoding,
        "content": content, "truncated": (offset + len(data)) < size,
    }


# ---------------------------------------------------------------------------
# OSINT / Threat-intel / YARA / Report tools
# ---------------------------------------------------------------------------

# Per-tool budgets. Keep results tight so the LLM feedback loop stays cheap.
_WEB_SEARCH_SNIPPET_CAP = 240
_THREAT_INTEL_TIMEOUT   = 10
_RULES_DIR              = (OUTPUTS_DIR.parent / "rules")
_DEFAULT_YARA_RULES     = _RULES_DIR / "malware_rules.yar"

# IOC type detection (used by threat_intel + UI).
_RE_IPV4    = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_RE_IPV6    = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")
_RE_MD5     = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1    = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256  = re.compile(r"^[a-fA-F0-9]{64}$")
_RE_DOMAIN  = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def _ioc_kind(indicator: str) -> str:
    s = indicator.strip()
    if _RE_IPV4.match(s):
        try:
            if all(0 <= int(p) <= 255 for p in s.split(".")):
                return "ipv4"
        except ValueError:
            pass
    if _RE_IPV6.match(s) and ":" in s:
        return "ipv6"
    if _RE_MD5.match(s):    return "md5"
    if _RE_SHA1.match(s):   return "sha1"
    if _RE_SHA256.match(s): return "sha256"
    if _RE_DOMAIN.match(s): return "domain"
    return "unknown"


def _tool_web_search(args: dict, ctx: dict) -> dict:
    """DuckDuckGo HTML search. No API key — scrapes the lite endpoint."""
    query = str(args.get("query", "")).strip()
    if not query:
        return {"error": "query is required"}
    max_hits = max(1, min(int(args.get("max_hits", 5) or 5), 15))
    timeout  = max(2, min(int(args.get("timeout", 12) or 12), 30))

    try:
        from urllib.parse import quote_plus
        from bs4 import BeautifulSoup
    except ImportError as e:
        return {"error": f"missing dependency: {e.name}"}

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) m3mx-osint/1.0",
        "Accept-Language": "en-US,en;q=0.8",
    }
    url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
    except Exception as e:
        return {"error": f"search request failed: {e}"}

    soup = BeautifulSoup(r.text, "html.parser")
    hits: list[dict] = []
    for div in soup.select("div.result")[:max_hits]:
        a = div.select_one("a.result__a")
        snip = div.select_one(".result__snippet")
        if not a:
            continue
        title = (a.get_text(" ", strip=True) or "")[:200]
        href  = a.get("href") or ""
        # DDG sometimes wraps real URLs in /l/?uddg=<encoded>; clean it.
        if href.startswith("/l/?") or href.startswith("//duckduckgo.com/l/?"):
            from urllib.parse import urlparse, parse_qs, unquote
            q = parse_qs(urlparse(href).query)
            href = unquote(q.get("uddg", [href])[0])
        snippet = (snip.get_text(" ", strip=True) if snip else "")[:_WEB_SEARCH_SNIPPET_CAP]
        hits.append({"title": title, "url": href, "snippet": snippet})

    return {"query": query, "count": len(hits), "results": hits}


def _tool_threat_intel(args: dict, ctx: dict) -> dict:
    """Reputation lookup. Routes to AbuseIPDB (IPs) or VirusTotal (hashes/domains)."""
    indicator = str(args.get("indicator", "")).strip()
    if not indicator:
        return {"error": "indicator is required"}
    timeout = max(2, min(int(args.get("timeout", _THREAT_INTEL_TIMEOUT) or _THREAT_INTEL_TIMEOUT), 30))
    kind = _ioc_kind(indicator)
    if kind == "unknown":
        return {"error": f"could not classify indicator: {indicator!r}"}

    cfg  = load_config()
    keys = cfg.get("ai", {}).get("api_keys", {})
    base = {"indicator": indicator, "kind": kind}

    try:
        if kind in ("ipv4", "ipv6"):
            key = keys.get("abuseipdb") or os.environ.get("ABUSEIPDB_KEY", "")
            if not key:
                return {**base, "error": "AbuseIPDB API key not configured "
                                          "(Settings → AI → api_keys.abuseipdb)"}
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": indicator, "maxAgeInDays": "90"},
                headers={"Key": key, "Accept": "application/json"},
                timeout=timeout,
            )
            r.raise_for_status()
            d = r.json().get("data", {}) or {}
            return {
                **base, "source": "abuseipdb",
                "abuse_confidence":  d.get("abuseConfidenceScore"),
                "total_reports":     d.get("totalReports"),
                "last_reported_at":  d.get("lastReportedAt"),
                "country":           d.get("countryCode"),
                "isp":               d.get("isp"),
                "domain":            d.get("domain"),
                "usage_type":        d.get("usageType"),
                "is_tor":            d.get("isTor"),
                "is_whitelisted":    d.get("isWhitelisted"),
            }

        if kind in ("md5", "sha1", "sha256"):
            key = keys.get("virustotal") or os.environ.get("VT_API_KEY", "")
            if not key:
                return {**base, "error": "VirusTotal API key not configured "
                                          "(Settings → AI → api_keys.virustotal)"}
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{indicator}",
                headers={"x-apikey": key},
                timeout=timeout,
            )
            if r.status_code == 404:
                return {**base, "source": "virustotal", "found": False}
            r.raise_for_status()
            attrs = ((r.json() or {}).get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            return {
                **base, "source": "virustotal", "found": True,
                "malicious":   stats.get("malicious"),
                "suspicious":  stats.get("suspicious"),
                "harmless":    stats.get("harmless"),
                "undetected":  stats.get("undetected"),
                "total":       sum(stats.values()) if stats else None,
                "names":       (attrs.get("names") or [])[:5],
                "type":        attrs.get("type_description"),
                "size":        attrs.get("size"),
                "first_seen":  attrs.get("first_submission_date"),
                "popular_threat_classification":
                    (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
            }

        if kind == "domain":
            key = keys.get("virustotal") or os.environ.get("VT_API_KEY", "")
            if not key:
                return {**base, "error": "VirusTotal API key not configured"}
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{indicator}",
                headers={"x-apikey": key},
                timeout=timeout,
            )
            if r.status_code == 404:
                return {**base, "source": "virustotal", "found": False}
            r.raise_for_status()
            attrs = ((r.json() or {}).get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            return {
                **base, "source": "virustotal", "found": True,
                "malicious":  stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "harmless":   stats.get("harmless"),
                "categories": list((attrs.get("categories") or {}).values())[:5],
                "registrar":  attrs.get("registrar"),
                "creation_date": attrs.get("creation_date"),
            }
    except requests.HTTPError as e:
        return {**base, "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except Exception as e:
        return {**base, "error": f"{type(e).__name__}: {e}"}

    return {**base, "error": "unsupported indicator kind"}


def _tool_yara_scan(args: dict, ctx: dict) -> dict:
    """
    Run Vol3 windows.vadyarascan with a YARA rules file. Thin wrapper around
    forensics.run_plugin so it gets all the tool's machinery: cache, partial-
    dump support, profile auto-detect, v3→v2 fallback, CSV parsing.
    """
    if not ctx.get("image_path"):
        return {"error": "no memory image loaded"}

    rules = str(args.get("rules_file") or _DEFAULT_YARA_RULES)
    rp = Path(rules).expanduser().resolve()
    if not rp.exists():
        return {"error": f"YARA rules file not found: {rp}. "
                         "Bootstrap with: "
                         "curl -L -o rules/malware_rules.yar "
                         "https://raw.githubusercontent.com/Kirandawadi/volatility3-mcp/main/malware_rules.yar"}

    extra = [f"--yara-file={rp}"]
    pid = args.get("pid")
    if pid is not None:
        try:
            extra.append(f"--pid={int(pid)}")
        except (TypeError, ValueError):
            return {"error": f"invalid pid: {pid!r}"}

    result = forensics.run_plugin(
        ctx["image_path"], "vadyarascan",
        version="v3",                 # Vol2 has no equivalent in our registry
        timeout=ctx.get("timeout", 600),
        vol_paths=ctx.get("vol_paths"),
        extra_params=" ".join(extra),
    )
    d = result.to_dict()
    if d.get("rows") and len(d["rows"]) > 50:
        d["rows"] = d["rows"][:50]
        d["truncated_rows"] = True
    if d.get("output") and len(d["output"]) > 16000:
        d["output"] = d["output"][:16000] + "\n…[truncated]"
    d["rules_file"] = str(rp)
    return d


def _tool_generate_report(args: dict, ctx: dict) -> dict:
    """
    Render an enterprise-styled PDF for a Full Analysis case.
    Reads findings.jsonl + attack_story.md, writes report.pdf next to them.
    Uses weasyprint (HTML→PDF). Falls back to a markdown dump if weasyprint
    isn't importable for any reason.
    """
    image = ctx.get("image_path")
    case_id = (args.get("case_id") or "").strip()
    if not case_id:
        if not image:
            return {"error": "case_id or a loaded image is required"}
        case_id = Path(image).stem

    case_dir = OUTPUTS_DIR / "full_analysis" / case_id
    findings_path = case_dir / "findings.jsonl"
    story_path    = case_dir / "attack_story.md"
    if not findings_path.exists():
        return {"error": f"no triage data at {findings_path} — "
                          "run Full Analysis first"}

    findings: list[dict] = []
    for line in findings_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line: continue
        try: findings.append(json.loads(line))
        except json.JSONDecodeError: continue

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_count[f.get("severity", "info")] = sev_count.get(f.get("severity", "info"), 0) + 1

    story_md = story_path.read_text(encoding="utf-8") if story_path.exists() else ""
    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z").strip()

    html = _build_report_html(
        case_id=case_id, image=image or "(unknown)",
        findings=findings, sev_count=sev_count,
        story_md=story_md, generated_at=generated_at,
    )

    out_pdf = case_dir / "report.pdf"
    try:
        from weasyprint import HTML
        HTML(string=html, base_url=str(case_dir)).write_pdf(target=str(out_pdf))
        size = out_pdf.stat().st_size
        return {
            "ok": True, "path": str(out_pdf), "size_bytes": size,
            "case_id": case_id, "findings_count": len(findings),
            "severity_breakdown": sev_count,
            "generated_at": generated_at,
        }
    except ImportError:
        # Fallback: drop the rendered HTML so the analyst can print-to-PDF.
        out_html = case_dir / "report.html"
        out_html.write_text(html, encoding="utf-8")
        return {
            "ok": True, "fallback": "html",
            "path": str(out_html), "case_id": case_id,
            "warning": "weasyprint not installed — wrote HTML instead",
            "findings_count": len(findings),
        }
    except Exception as e:
        log.exception("PDF render failed")
        return {"error": f"{type(e).__name__}: {e}"}


def _build_report_html(*, case_id, image, findings, sev_count,
                       story_md, generated_at) -> str:
    """Self-contained HTML for the PDF render."""
    def esc(s): return (str(s).replace("&","&amp;").replace("<","&lt;")
                              .replace(">","&gt;").replace('"','&quot;'))

    sev_chip = lambda s: f'<span class="sev sev-{esc(s)}">{esc(s).upper()}</span>'

    rows_html = "\n".join(
        f"""<tr>
              <td class="fid">{esc(f.get('id',''))}</td>
              <td>{sev_chip(f.get('severity','info'))}</td>
              <td><div class="ttl">{esc(f.get('title',''))}</div>
                  <div class="dsc">{esc(f.get('description',''))}</div></td>
              <td><code>{esc(f.get('plugin',''))}</code></td>
              <td>{' '.join(f'<span class="mitre">{esc(t)}</span>' for t in (f.get('tags') or []))}</td>
              <td>{int(round((f.get('confidence') or 0)*100))}%</td>
            </tr>"""
        for f in findings
    ) or '<tr><td colspan="6" class="empty">No findings.</td></tr>'

    # Tiny markdown → HTML for the story (headers, bold, lists).
    story_html = esc(story_md or "")
    story_html = re.sub(r"^### (.*)$",  r"<h3>\1</h3>", story_html, flags=re.M)
    story_html = re.sub(r"^## (.*)$",   r"<h2>\1</h2>", story_html, flags=re.M)
    story_html = re.sub(r"^# (.*)$",    r"<h1>\1</h1>", story_html, flags=re.M)
    story_html = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", story_html)
    story_html = re.sub(r"^[ \t]*-\s+(.*)$", r"<li>\1</li>", story_html, flags=re.M)
    story_html = re.sub(r"(?:<li>.*?</li>\s*)+", lambda m: f"<ul>{m.group(0)}</ul>", story_html, flags=re.S)
    story_html = re.sub(r"\n{2,}", "</p><p>", story_html)
    story_html = f"<p>{story_html}</p>" if story_html.strip() else "<p><em>No attack story available.</em></p>"
    story_html = re.sub(r"(F-\d{2,4})", r'<span class="fid-ref">\1</span>', story_html)

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>m3mx Forensic Report — {esc(case_id)}</title>
<style>
@page {{ size: A4; margin: 18mm 16mm; @bottom-center {{ content: "m3mx · " counter(page) " / " counter(pages); font: 9pt 'DejaVu Sans'; color:#888; }} }}
body {{ font-family: 'DejaVu Sans', sans-serif; color:#1f2937; font-size:10.5pt; line-height:1.45; }}
.cover {{ padding: 60mm 0 30mm; text-align:center; }}
.cover .kicker {{ letter-spacing:.18em; font-size:9pt; color:#6b7280; text-transform:uppercase; }}
.cover h1 {{ font-size:30pt; margin:8pt 0 4pt; color:#111827; }}
.cover .case {{ font-family:'DejaVu Sans Mono'; font-size:11pt; color:#374151; }}
.cover .meta {{ margin-top:28pt; color:#6b7280; font-size:9.5pt; }}
.kpis {{ display:grid; grid-template-columns: repeat(5,1fr); gap:6mm; margin: 10mm 0; }}
.kpi {{ border:1px solid #e5e7eb; border-radius:8pt; padding:8pt 10pt; }}
.kpi b {{ font-size:18pt; display:block; }}
.kpi span {{ font-size:8.5pt; color:#6b7280; text-transform:uppercase; letter-spacing:.05em; }}
.kpi.crit b {{ color:#dc2626; }} .kpi.crit {{ background:#fef2f2; border-color:#fecaca; }}
.kpi.high b {{ color:#d97706; }} .kpi.high {{ background:#fffbeb; border-color:#fed7aa; }}
h1.section, h2.section {{ border-bottom:2px solid #4f46e5; padding-bottom:4pt; margin-top:8mm; }}
table {{ width:100%; border-collapse:collapse; font-size:9pt; }}
th {{ background:#f3f4f6; text-align:left; padding:6pt 8pt; border-bottom:2px solid #e5e7eb; }}
td {{ padding:6pt 8pt; border-bottom:1px solid #f1f5f9; vertical-align:top; }}
.sev {{ display:inline-block; padding:1pt 6pt; border-radius:8pt; font-size:8pt; font-weight:700; letter-spacing:.04em; }}
.sev-critical {{ background:#fee2e2; color:#991b1b; border:.5pt solid #f87171; }}
.sev-high     {{ background:#ffedd5; color:#9a3412; border:.5pt solid #fb923c; }}
.sev-medium   {{ background:#fef3c7; color:#92400e; border:.5pt solid #fbbf24; }}
.sev-low      {{ background:#dbeafe; color:#1e40af; border:.5pt solid #60a5fa; }}
.sev-info     {{ background:#e5e7eb; color:#374151; border:.5pt solid #9ca3af; }}
.mitre {{ display:inline-block; margin:0 2pt 1pt 0; padding:1pt 5pt; border-radius:3pt;
         background:#eef2ff; color:#3730a3; font-family:'DejaVu Sans Mono'; font-size:7.5pt; border:.5pt solid #c7d2fe; }}
.fid    {{ font-family:'DejaVu Sans Mono'; background:#f3f4f6; padding:2pt 5pt; border-radius:3pt; font-size:8.5pt; }}
.fid-ref{{ font-family:'DejaVu Sans Mono'; background:#fef3c7; color:#92400e; padding:0 4pt; border-radius:2pt; font-size:8.5pt; border:.5pt solid #fcd34d; }}
.ttl {{ font-weight:600; color:#111827; }}
.dsc {{ color:#4b5563; font-size:8.5pt; margin-top:2pt; }}
.story {{ margin-top:6mm; }}
.story h1, .story h2, .story h3 {{ color:#3730a3; margin:6mm 0 2mm; }}
.story p {{ margin:2mm 0; }}
.story ul {{ margin: 2mm 0 4mm 6mm; }}
.empty {{ text-align:center; color:#9ca3af; padding:14pt; }}
code {{ font-family:'DejaVu Sans Mono'; font-size:8.5pt; background:#f3f4f6; padding:1pt 4pt; border-radius:2pt; }}
</style></head><body>

<section class="cover">
  <div class="kicker">m3mx forensics report</div>
  <h1>Full Analysis</h1>
  <div class="case">{esc(case_id)}</div>
  <div class="meta">
    Generated {esc(generated_at)}<br>
    Source image: <code>{esc(image)}</code><br>
    {len(findings)} finding(s)
  </div>
</section>

<h2 class="section">Executive Summary</h2>
<div class="kpis">
  <div class="kpi crit"><b>{sev_count.get('critical',0)}</b><span>Critical</span></div>
  <div class="kpi high"><b>{sev_count.get('high',0)}</b><span>High</span></div>
  <div class="kpi"><b>{sev_count.get('medium',0)}</b><span>Medium</span></div>
  <div class="kpi"><b>{sev_count.get('low',0)}</b><span>Low</span></div>
  <div class="kpi"><b>{sev_count.get('info',0)}</b><span>Info</span></div>
</div>

<h2 class="section">AI Attack Story</h2>
<div class="story">{story_html}</div>

<h2 class="section">Findings</h2>
<table>
  <thead><tr><th>ID</th><th>Severity</th><th>Title / Description</th><th>Plugin</th><th>MITRE ATT&amp;CK</th><th>Conf.</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table>

</body></html>"""


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

TOOLS: dict[str, Callable[[dict, dict], dict]] = {
    "run_volatility":  _tool_run_volatility,
    "run_shell":       _tool_run_shell,
    "read_file":       _tool_read_file,
    "list_outputs":    _tool_list_outputs,
    "read_output":     _tool_read_output,
    "web_search":      _tool_web_search,
    "threat_intel":    _tool_threat_intel,
    "yara_scan":       _tool_yara_scan,
    "generate_report": _tool_generate_report,
}


def dispatch_tool(name: str, args: dict, ctx: dict) -> dict:
    """Execute a tool call from the LLM. Rejects anything not in TOOLS."""
    if name not in TOOLS:
        log_security_violation(name, f"unknown tool '{name}'")
        return {"error": f"unknown tool '{name}'"}
    try:
        return TOOLS[name](args or {}, ctx)
    except Exception as e:                                  # pragma: no cover
        log.exception("tool dispatch error")
        return {"error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# Build system prompt from context
# ---------------------------------------------------------------------------

def build_system_prompt(ctx: dict) -> str:
    # The new dual-mode prompt has no placeholder interpolation.
    # ctx is kept on the signature for backwards compat with callers.
    return SYSTEM_PROMPT_TEMPLATE


# ---------------------------------------------------------------------------
# Chat history persistence
# ---------------------------------------------------------------------------

def load_history() -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text())
    except Exception:
        return []


def save_history(history: list[dict]) -> None:
    HISTORY_FILE.parent.mkdir(exist_ok=True, parents=True)
    HISTORY_FILE.write_text(json.dumps(history[-200:], indent=2))


def reset_history() -> None:
    if HISTORY_FILE.exists():
        HISTORY_FILE.unlink()


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

def _ollama_stream(messages: list[dict], model: str, cfg: dict) -> Iterable[dict]:
    url = cfg.get("ai", {}).get("ollama_url", "http://localhost:11434").rstrip("/")
    try:
        r = requests.post(
            f"{url}/api/chat",
            json={"model": model or "llama3.1", "messages": messages, "stream": True,
                  "options": {
                      "temperature": cfg["ai"].get("temperature", 0.2),
                      "num_predict": cfg["ai"].get("max_tokens", 1000),
                  }},
            stream=True, timeout=300,
        )
        r.raise_for_status()
        for line in r.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                chunk = json.loads(line)
            except json.JSONDecodeError:
                continue
            if chunk.get("done"):
                yield {"type": "done",
                       "usage": {"input": chunk.get("prompt_eval_count", 0),
                                 "output": chunk.get("eval_count", 0)},
                       "model": chunk.get("model", model)}
                return
            piece = chunk.get("message", {}).get("content", "")
            if piece:
                yield {"type": "token", "content": piece}
    except Exception as e:
        yield {"type": "error", "message": f"Ollama: {e}"}


def _openai_stream(messages: list[dict], model: str, cfg: dict) -> Iterable[dict]:
    key = get_api_key("openai")
    if not key:
        yield {"type": "error", "message": "OpenAI API key not configured."}
        return
    try:
        from openai import OpenAI
    except ImportError:
        yield {"type": "error", "message": "openai SDK not installed. Run: pip install openai"}
        return

    try:
        client = OpenAI(api_key=key)
        stream = client.chat.completions.create(
            model=model or "gpt-5",
            messages=messages, stream=True,
            temperature=cfg["ai"].get("temperature", 0.2),
            max_tokens=cfg["ai"].get("max_tokens", 1000),
        )
        in_toks = out_toks = 0
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                piece = chunk.choices[0].delta.content
                out_toks += len(piece.split())
                yield {"type": "token", "content": piece}
        yield {"type": "done", "usage": {"input": in_toks, "output": out_toks}, "model": model}
    except Exception as e:
        yield {"type": "error", "message": f"OpenAI: {e}"}


def _anthropic_stream(messages: list[dict], model: str, cfg: dict) -> Iterable[dict]:
    key = get_api_key("anthropic")
    if not key:
        yield {"type": "error", "message": "Anthropic API key not configured."}
        return
    try:
        import anthropic
    except ImportError:
        yield {"type": "error", "message": "anthropic SDK not installed. Run: pip install anthropic"}
        return

    # Anthropic wants system separate from messages list
    system = next((m["content"] for m in messages if m["role"] == "system"), "")
    convo  = [m for m in messages if m["role"] != "system"]

    try:
        client = anthropic.Anthropic(api_key=key)
        with client.messages.stream(
            model=model or "claude-sonnet-4-6",
            system=system,
            messages=convo,
            max_tokens=cfg["ai"].get("max_tokens", 1000),
            temperature=cfg["ai"].get("temperature", 0.2),
        ) as stream:
            for text in stream.text_stream:
                yield {"type": "token", "content": text}
            final = stream.get_final_message()
            yield {"type": "done",
                   "usage": {"input": final.usage.input_tokens,
                             "output": final.usage.output_tokens},
                   "model": model}
    except Exception as e:
        yield {"type": "error", "message": f"Anthropic: {e}"}


def _glm_stream(messages: list[dict], model: str, cfg: dict) -> Iterable[dict]:
    """
    ZhipuAI GLM (bigmodel.cn). OpenAI-compatible endpoint at
    https://open.bigmodel.cn/api/paas/v4/ — reuses the openai SDK.
    Default model: glm-5 (falls back to glm-4-plus if you've typed an
    older name into Settings).
    """
    key = get_api_key("glm") or get_api_key("zhipu")
    if not key:
        yield {"type": "error", "message": "GLM (ZhipuAI) API key not configured."}
        return
    try:
        from openai import OpenAI
    except ImportError:
        yield {"type": "error", "message": "openai SDK not installed. Run: pip install openai"}
        return

    base_url = (cfg.get("ai", {}).get("glm_base_url")
                or "https://open.bigmodel.cn/api/paas/v4/")
    try:
        client = OpenAI(api_key=key, base_url=base_url)
        stream = client.chat.completions.create(
            model=model or "glm-5",
            messages=messages, stream=True,
            temperature=cfg["ai"].get("temperature", 0.2),
            max_tokens=cfg["ai"].get("max_tokens", 1000),
        )
        in_toks = out_toks = 0
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                piece = chunk.choices[0].delta.content
                out_toks += len(piece.split())
                yield {"type": "token", "content": piece}
        yield {"type": "done", "usage": {"input": in_toks, "output": out_toks},
               "model": model or "glm-5"}
    except Exception as e:
        yield {"type": "error", "message": f"GLM: {e}"}


def _agentrouter_stream(messages: list[dict], model: str, cfg: dict) -> Iterable[dict]:
    """
    agentrouter.org — multi-model OpenAI-compatible relay. Hosts Claude
    (haiku-4-5, opus-4-6), DeepSeek (r1, v3.1, v3.2), and GLM (4.5/4.6/5.1)
    behind a single sk-… key. Reuses the openai SDK with a custom base.
    """
    key = get_api_key("agentrouter")
    if not key:
        yield {"type": "error", "message": "agentrouter API key not configured."}
        return
    try:
        from openai import OpenAI
    except ImportError:
        yield {"type": "error", "message": "openai SDK not installed. Run: pip install openai"}
        return

    base_url = (cfg.get("ai", {}).get("agentrouter_base_url")
                or "https://agentrouter.org/v1").rstrip("/") + "/"
    try:
        client = OpenAI(api_key=key, base_url=base_url)
        stream = client.chat.completions.create(
            model=model or "claude-opus-4-6",
            messages=messages, stream=True,
            temperature=cfg["ai"].get("temperature", 0.2),
            max_tokens=cfg["ai"].get("max_tokens", 1000),
        )
        in_toks = out_toks = 0
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                piece = chunk.choices[0].delta.content
                out_toks += len(piece.split())
                yield {"type": "token", "content": piece}
        yield {"type": "done", "usage": {"input": in_toks, "output": out_toks},
               "model": model or "claude-opus-4-6"}
    except Exception as e:
        yield {"type": "error", "message": f"agentrouter: {e}"}


def _google_stream(messages: list[dict], model: str, cfg: dict) -> Iterable[dict]:
    key = get_api_key("google")
    if not key:
        yield {"type": "error", "message": "Google API key not configured."}
        return
    try:
        import google.generativeai as genai
    except ImportError:
        yield {"type": "error", "message": "google-generativeai not installed."}
        return

    try:
        genai.configure(api_key=key)
        m = genai.GenerativeModel(
            model_name=model or "gemini-2.5-pro",
            system_instruction=next((x["content"] for x in messages if x["role"] == "system"), ""),
            generation_config={
                "temperature": cfg["ai"].get("temperature", 0.2),
                "max_output_tokens": cfg["ai"].get("max_tokens", 1000),
            },
        )
        # Convert non-system to Gemini format
        hist = []
        for msg in messages:
            if msg["role"] == "system": continue
            role = "user" if msg["role"] == "user" else "model"
            hist.append({"role": role, "parts": [msg["content"]]})

        resp = m.generate_content(hist, stream=True)
        for chunk in resp:
            # `chunk.text` raises on empty parts (e.g. the final STOP-only
            # chunk Gemini emits). Walk parts manually so we never trigger
            # the SDK's strict accessor and miss an actual final token.
            try:
                cands = getattr(chunk, "candidates", None) or []
                for cand in cands:
                    parts = getattr(getattr(cand, "content", None), "parts", None) or []
                    for p in parts:
                        t = getattr(p, "text", None)
                        if t:
                            yield {"type": "token", "content": t}
            except Exception:
                pass
        # Gemini usage_metadata after final chunk
        u = getattr(resp, "usage_metadata", None)
        yield {"type": "done",
               "usage": {"input":  getattr(u, "prompt_token_count", 0),
                         "output": getattr(u, "candidates_token_count", 0)},
               "model": model}
    except Exception as e:
        yield {"type": "error", "message": f"Google: {e}"}


PROVIDER_STREAM = {
    "ollama":      _ollama_stream,
    "openai":      _openai_stream,
    "anthropic":   _anthropic_stream,
    "google":      _google_stream,
    "glm":         _glm_stream,
    "zhipu":       _glm_stream,           # alias
    "agentrouter": _agentrouter_stream,   # multi-model proxy (Claude/DeepSeek/GLM)
}


# ---------------------------------------------------------------------------
# Main entry: stream_chat
# ---------------------------------------------------------------------------

_TOOL_CALL_RE = re.compile(
    r"```tool\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE,
)


def _parse_tool_calls(text: str) -> list[dict]:
    """
    Provider-agnostic tool call parsing.

    The agent is instructed to emit tool calls as fenced JSON blocks:
        ```tool
        {"name": "run_volatility", "args": {"plugin": "pslist"}}
        ```
    Returns the parsed dicts (skipping invalid blocks).
    """
    calls = []
    for m in _TOOL_CALL_RE.finditer(text):
        try:
            d = json.loads(m.group(1).strip())
            if isinstance(d, dict) and "name" in d:
                calls.append({"name": d["name"], "args": d.get("args", {})})
        except json.JSONDecodeError:
            continue
    return calls


def stream_chat(user_message: str, ctx: dict,
                history: list[dict] | None = None) -> Generator[dict, None, None]:
    """
    Streams chat events. Call once per user message.

    Emits:
      {"type": "token", "content": str}
      {"type": "tool_call", "name": str, "args": dict}
      {"type": "tool_result", "name": str, "result": dict}
      {"type": "done", "usage": {...}, "model": str}
      {"type": "error", "message": str}
    """
    cfg = load_config()
    provider = cfg.get("ai", {}).get("provider", "ollama").lower()
    model    = cfg.get("ai", {}).get("model") or ""
    stream_fn = PROVIDER_STREAM.get(provider)
    if not stream_fn:
        yield {"type": "error", "message": f"Unknown provider: {provider}"}
        return

    tool_instructions = (
        "\n\nTo call a tool, emit a fenced JSON block inside your reply, exactly:\n"
        '```tool\n{"name": "run_shell", "args": {"command": "strings -n 8 /home/kali/M3MX.tool/m3mx-tool/uploads/memory.raw | head -n 50"}}\n```\n'
        "Other examples:\n"
        '```tool\n{"name": "run_volatility", "args": {"plugin": "pslist"}}\n```\n'
        '```tool\n{"name": "read_file", "args": {"path": "/home/kali/M3MX.tool/m3mx-tool/outputs/pslist.txt", "max_bytes": 8000}}\n```\n'
        "Valid tool names: run_volatility, run_shell, read_file, list_outputs, read_output.\n"
        "You may call multiple tools in one reply (each in its own fenced block); "
        "you will receive each result as a follow-up message and then may continue."
    )

    # Build message list
    sys_prompt = build_system_prompt(ctx) + tool_instructions
    messages: list[dict] = [{"role": "system", "content": sys_prompt}]
    for msg in (history or [])[-20:]:  # last 10 exchanges
        if msg.get("role") in ("user", "assistant"):
            messages.append({"role": msg["role"], "content": msg.get("content", "")})
    messages.append({"role": "user", "content": user_message})

    # Up to 8 tool-call rounds — enough for multi-step investigations
    # while still bounding runaway loops.
    collected_reply = ""
    last_model = model
    last_usage = {"input": 0, "output": 0}

    for turn in range(8):
        turn_text = ""
        for evt in stream_fn(messages, model, cfg):
            if evt["type"] == "token":
                turn_text += evt["content"]
                yield evt
            elif evt["type"] == "done":
                last_usage["input"]  += evt.get("usage", {}).get("input", 0)
                last_usage["output"] += evt.get("usage", {}).get("output", 0)
                last_model = evt.get("model", last_model)
            elif evt["type"] == "error":
                yield evt
                return

        collected_reply += turn_text

        # Parse tool calls in this turn's text
        calls = _parse_tool_calls(turn_text)
        if not calls:
            break

        # Dispatch each and feed result back
        messages.append({"role": "assistant", "content": turn_text})
        for call in calls:
            yield {"type": "tool_call", "name": call["name"], "args": call["args"]}
            result = dispatch_tool(call["name"], call["args"], ctx)
            yield {"type": "tool_result", "name": call["name"], "result": result}
            # Compact the result before feeding back
            feedback = json.dumps(result, default=str)
            if len(feedback) > 4000:
                feedback = feedback[:4000] + "…[truncated]"
            messages.append({
                "role": "user",
                "content": f"Tool `{call['name']}` result:\n```json\n{feedback}\n```",
            })

    # Persist history
    history = history or []
    history.append({"role": "user", "content": user_message,
                    "ts": datetime.datetime.utcnow().isoformat()})
    history.append({"role": "assistant", "content": collected_reply,
                    "model": last_model, "usage": last_usage,
                    "ts": datetime.datetime.utcnow().isoformat()})
    save_history(history)

    yield {"type": "done", "usage": last_usage, "model": last_model}


def test_connection(provider: str, model: str = "", api_key: str = "",
                    ollama_url: str = "http://localhost:11434") -> dict:
    """
    Lightweight liveness check for a provider. Uses the shortest
    possible call path so it returns quickly and costs almost no tokens.
    """
    t0 = datetime.datetime.now()
    def _done(ok: bool, msg: str = "", detail: str = "") -> dict:
        ms = (datetime.datetime.now() - t0).total_seconds() * 1000
        return {"ok": ok, "provider": provider, "model": model,
                "message": msg, "detail": detail, "elapsed_ms": int(ms)}

    provider = (provider or "").lower()

    if provider == "ollama":
        try:
            r = requests.get(f"{ollama_url.rstrip('/')}/api/tags", timeout=3)
            r.raise_for_status()
            models = [m.get("name") for m in r.json().get("models", [])]
            return _done(True, f"{len(models)} local model(s) available",
                         ", ".join(models[:5]))
        except Exception as e:
            return _done(False, "Ollama unreachable", str(e))

    if provider == "openai":
        key = api_key or get_api_key("openai")
        if not key: return _done(False, "no API key")
        try:
            from openai import OpenAI
            client = OpenAI(api_key=key)
            resp = client.chat.completions.create(
                model=model or "gpt-4o-mini",
                messages=[{"role":"user","content":"ping"}],
                max_tokens=1,
            )
            return _done(True, "reachable", resp.model)
        except Exception as e:
            return _done(False, "OpenAI test failed", str(e)[:160])

    if provider == "anthropic":
        key = api_key or get_api_key("anthropic")
        if not key: return _done(False, "no API key")
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=key)
            resp = client.messages.create(
                model=model or "claude-haiku-4-5",
                max_tokens=1,
                messages=[{"role":"user","content":"ping"}],
            )
            return _done(True, "reachable", resp.model)
        except Exception as e:
            return _done(False, "Anthropic test failed", str(e)[:160])

    if provider in ("glm", "zhipu"):
        key = api_key or get_api_key("glm") or get_api_key("zhipu")
        if not key: return _done(False, "no API key")
        try:
            from openai import OpenAI
            client = OpenAI(api_key=key,
                            base_url="https://open.bigmodel.cn/api/paas/v4/")
            resp = client.chat.completions.create(
                model=model or "glm-5",
                messages=[{"role":"user","content":"ping"}],
                max_tokens=1,
            )
            return _done(True, "reachable", resp.model)
        except Exception as e:
            return _done(False, "GLM test failed", str(e)[:160])

    if provider == "agentrouter":
        key = api_key or get_api_key("agentrouter")
        if not key: return _done(False, "no API key")
        try:
            from openai import OpenAI
            cfg = load_config()
            base_url = (cfg.get("ai", {}).get("agentrouter_base_url")
                        or "https://agentrouter.org/v1").rstrip("/") + "/"
            client = OpenAI(api_key=key, base_url=base_url)
            resp = client.chat.completions.create(
                model=model or "claude-opus-4-6",
                messages=[{"role":"user","content":"ping"}],
                max_tokens=1,
            )
            return _done(True, "reachable", resp.model)
        except Exception as e:
            return _done(False, "agentrouter test failed", str(e)[:160])

    if provider == "google":
        key = api_key or get_api_key("google")
        if not key: return _done(False, "no API key")
        try:
            import google.generativeai as genai
            genai.configure(api_key=key)
            m = genai.GenerativeModel(model or "gemini-2.5-flash")
            resp = m.generate_content("ping",
                generation_config={"max_output_tokens": 1, "temperature": 0})
            return _done(True, "reachable", getattr(resp, "model_version", model or ""))
        except Exception as e:
            return _done(False, "Google test failed", str(e)[:160])

    return _done(False, f"unknown provider: {provider}")


def current_context(app_config: dict) -> dict:
    """Build the live runtime context (image path, vol paths, profile, etc.)."""
    image = app_config.get("LOADED_IMAGE")
    cfg   = load_config()
    return {
        "image_path": image,
        "os_profile": forensics.cached_profile(image) if image else None,
        "output_dir": cfg.get("output", {}).get("directory") or str(OUTPUTS_DIR),
        "vol_paths":  app_config.get("VOLATILITY_PATHS", {}),
        "timeout":    cfg.get("volatility", {}).get("timeout_seconds", 600),
    }
