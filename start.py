#!/usr/bin/env python3
"""
m3mx tool — One-Click Launcher
==============================
Starts the m3mx memory-forensics platform with zero configuration.

Usage:
    python start.py

It will:
  1. Verify Python >= 3.9
  2. Install missing Python dependencies
  3. Detect Volatility 2 and/or Volatility 3
  4. Start the Flask web server
  5. Open http://localhost:5000 in your browser
"""
from __future__ import annotations

import os
import sys
import time
import shutil
import socket
import subprocess
import threading
import webbrowser
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
REQUIREMENTS = ROOT / "requirements.txt"
HOST = "0.0.0.0"
PORT = 5000

# ---------------------------------------------------------------------------
# Pretty terminal output
# ---------------------------------------------------------------------------

class C:
    """Terminal colors. Falls back to no-op on Windows CMD without ANSI."""
    R = "\033[0m"
    B = "\033[1m"
    DIM = "\033[2m"
    PURPLE = "\033[38;5;141m"
    INDIGO = "\033[38;5;99m"
    CYAN = "\033[38;5;87m"
    GREEN = "\033[38;5;84m"
    YELLOW = "\033[38;5;221m"
    RED = "\033[38;5;203m"
    GREY = "\033[38;5;245m"

    @classmethod
    def disable(cls) -> None:
        for k in list(vars(cls)):
            if not k.startswith("_") and isinstance(getattr(cls, k), str) and getattr(cls, k).startswith("\033"):
                setattr(cls, k, "")


if os.name == "nt" and not os.environ.get("WT_SESSION"):
    try:
        import colorama  # type: ignore
        colorama.just_fix_windows_console()
    except Exception:
        C.disable()


BANNER = r"""
   ███╗   ███╗██████╗ ███╗   ███╗██╗  ██╗    ████████╗ ██████╗  ██████╗ ██╗
   ████╗ ████║╚════██╗████╗ ████║╚██╗██╔╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║
   ██╔████╔██║ █████╔╝██╔████╔██║ ╚███╔╝        ██║   ██║   ██║██║   ██║██║
   ██║╚██╔╝██║ ╚═══██╗██║╚██╔╝██║ ██╔██╗        ██║   ██║   ██║██║   ██║██║
   ██║ ╚═╝ ██║██████╔╝██║ ╚═╝ ██║██╔╝ ██╗       ██║   ╚██████╔╝╚██████╔╝███████╗
   ╚═╝     ╚═╝╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
"""


def log(tag: str, msg: str, color: str = C.PURPLE) -> None:
    print(f"{color}[{tag}]{C.R} {msg}")


def info(msg: str) -> None:   log("INFO", msg, C.CYAN)
def ok(msg: str) -> None:     log(" OK ", msg, C.GREEN)
def warn(msg: str) -> None:   log("WARN", msg, C.YELLOW)
def err(msg: str) -> None:    log("ERR!", msg, C.RED)


def banner() -> None:
    print(f"{C.PURPLE}{BANNER}{C.R}")
    print(f"   {C.B}{C.PURPLE}m3mx tool{C.R} {C.GREY}|{C.R} {C.INDIGO}Memory Forensics AI Platform{C.R}")
    


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def check_python() -> None:
    if sys.version_info < (3, 9):
        err(f"Python 3.9+ required, but running {sys.version.split()[0]}.")
        sys.exit(1)
    ok(f"Python {sys.version.split()[0]} detected.")


def _pip_install(args: list[str]) -> bool:
    cmd = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *args]
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False


def _import_available(module: str) -> bool:
    try:
        __import__(module)
        return True
    except ImportError:
        return False


def check_requirements() -> None:
    # Lightweight check: only install if Flask is missing. A full pip install -r
    # is slow every launch; we trust the user after first run.
    if _import_available("flask") and _import_available("requests") and _import_available("yaml"):
        ok("Python dependencies already installed.")
        return

    if not REQUIREMENTS.exists():
        err(f"requirements.txt not found at {REQUIREMENTS}")
        sys.exit(1)

    info("Installing Python dependencies (first run only — may take a minute)…")
    if _pip_install(["-r", str(REQUIREMENTS)]):
        ok("Dependencies installed.")
    else:
        err("pip install failed. Run manually:\n       "
            f"{sys.executable} -m pip install -r {REQUIREMENTS}")
        sys.exit(1)


def ensure_ollama_running(host: str = "127.0.0.1", port: int = 11434) -> bool:
    """Auto-start the Ollama daemon if the binary is installed but not serving."""
    # Already running?
    try:
        with socket.create_connection((host, port), timeout=0.4):
            ok(f"Ollama already running on {host}:{port}")
            return True
    except OSError:
        pass

    bin_path = shutil.which("ollama")
    if not bin_path:
        warn("Ollama not installed — AI chat will need OpenAI/Anthropic/Google.")
        return False

    info(f"Starting Ollama daemon ({bin_path}) in the background…")
    log_file = Path.home() / ".local" / "share" / "ollama" / "serve.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    lib_dir = Path.home() / ".local" / "share" / "ollama" / "lib" / "ollama"
    if lib_dir.exists():
        env["LD_LIBRARY_PATH"] = f"{lib_dir}:{env.get('LD_LIBRARY_PATH', '')}"

    try:
        # setsid → process survives our parent shell dying
        subprocess.Popen(
            [bin_path, "serve"],
            stdout=open(log_file, "ab"), stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
    except Exception as e:
        warn(f"Could not start Ollama: {e}")
        return False

    # Poll up to 5 s
    for _ in range(20):
        time.sleep(0.25)
        try:
            with socket.create_connection((host, port), timeout=0.3):
                ok(f"Ollama started on {host}:{port}")
                return True
        except OSError:
            pass
    warn("Ollama did not respond within 5 s — check ~/.local/share/ollama/serve.log")
    return False


def detect_volatility() -> dict:
    """
    Resolve Vol2/Vol3 paths.

    Priority:
        1. config.json → volatility.vol2_path / vol3_path  (analyst's pick)
        2. PATH lookup of well-known binary names         (best-effort)
    """
    import json
    result = {"vol2": None, "vol3": None}

    # 1. Honour explicit config first.
    cfg_path = ROOT / "config.json"
    if cfg_path.exists():
        try:
            v = (json.loads(cfg_path.read_text()) or {}).get("volatility", {}) or {}
            for key, cfg_key in (("vol2", "vol2_path"), ("vol3", "vol3_path")):
                p = (v.get(cfg_key) or "").strip()
                if p and Path(p).exists():
                    result[key] = p
        except Exception as e:
            warn(f"Could not read config.json volatility paths: {e}")

    # 2. Fall back to PATH detection only for whichever slot is still empty.
    if not result["vol3"]:
        for candidate in ("vol", "volatility3", "vol3"):
            path = shutil.which(candidate)
            if path:
                result["vol3"] = path
                break
    if not result["vol2"]:
        for candidate in ("vol2", "volatility", "vol.py", "volatility2", "vol2.py"):
            path = shutil.which(candidate)
            if path:
                result["vol2"] = path
                break

    if result["vol3"]:
        ok(f"Volatility 3: {result['vol3']}")
    else:
        warn("Volatility 3 not found. Install it or set vol3_path in config.json.")

    if result["vol2"]:
        ok(f"Volatility 2: {result['vol2']}")
    else:
        warn("Volatility 2 not found. Install it or set vol2_path in config.json.")

    if not result["vol2"] and not result["vol3"]:
        warn("Neither Volatility version detected. m3mx will still start, "
             "but plugins cannot be executed until one is installed.")

    return result


def port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        try:
            s.connect((host, port))
            return True
        except OSError:
            return False


def pick_port(host: str, base: int) -> int:
    port = base
    while port_in_use(host, port) and port < base + 20:
        port += 1
    return port


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------

def open_browser(url: str, delay: float = 1.2) -> None:
    def _open() -> None:
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_open, daemon=True).start()


def run_server(host: str, port: int, vol_paths: dict) -> None:
    # Import after dependency install
    from app.main import create_app

    app = create_app(volatility_paths=vol_paths)
    url = f"http://{host}:{port}"

    print()
    print(f"   {C.B}{C.PURPLE}▶ m3mx tool is running{C.R}")
    print(f"     {C.GREY}URL:{C.R} {C.CYAN}{url}{C.R}")
    print(f"     {C.GREY}Stop:{C.R} Ctrl+C")
    print()

    open_browser(url)
    # Disable the default reloader — it runs the launcher twice.
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


def main() -> None:
    banner()
    check_python()
    check_requirements()

    vol_paths = detect_volatility()
    ensure_ollama_running()

    port = pick_port(HOST, PORT)
    if port != PORT:
        warn(f"Port {PORT} busy; using {port} instead.")

    try:
        run_server(HOST, port, vol_paths)
    except KeyboardInterrupt:
        print()
        info("Shutting down. Goodbye.")


if __name__ == "__main__":
    main()
