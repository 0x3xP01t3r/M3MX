"""Bounded subprocess output and process-group cleanup for untrusted evidence."""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time


def child_environment() -> dict:
    # Forensic child processes have no need for provider credentials.
    return {k: v for k, v in os.environ.items() if not any(
        word in k.upper() for word in ("API_KEY", "SECRET", "TOKEN", "PASSWORD", "ABUSEIPDB_KEY"))}


def stop_process(proc) -> None:
    # The leader can exit while descendants still hold its output pipes open.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait()


def run_command(cmd: list[str], *, timeout: int = 600, cwd=None, env=None,
                max_bytes: int | None = None) -> subprocess.CompletedProcess:
    """No shell, bounded capture, and kill the entire process group on failure."""
    limit = max_bytes or min(int(os.environ.get("M3MX_PROCESS_OUTPUT_BYTES", 64 * 1024**2)), 256 * 1024**2)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=cwd, env=env or child_environment(), start_new_session=True)
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    total = 0
    deadline = time.monotonic() + timeout
    try:
        for name in chunks:
            selector.register(getattr(proc, name), selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(cmd, timeout, bytes(chunks["stdout"]), bytes(chunks["stderr"]))
            for key, _ in selector.select(min(remaining, 0.2)):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                remaining_bytes = max(0, limit - total)
                chunks[key.data].extend(data[:remaining_bytes])
                total += len(data)
                if total > limit:
                    stop_process(proc)
                    chunks["stderr"].extend(b"\nOutput limit exceeded; command stopped. Narrow the plugin or command scope.")
                    return subprocess.CompletedProcess(cmd, 1, chunks["stdout"].decode("utf-8", "replace"),
                                                       chunks["stderr"].decode("utf-8", "replace"))
        proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        return subprocess.CompletedProcess(cmd, proc.returncode,
            chunks["stdout"].decode("utf-8", "replace"), chunks["stderr"].decode("utf-8", "replace"))
    finally:
        selector.close()
        stop_process(proc)
        proc.stdout.close()
        proc.stderr.close()


def stream_command(cmd: list[str], *, timeout: int = 600, env=None):
    """Yield bounded live text chunks, then an exit event; close kills children."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env or child_environment(), start_new_session=True)
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    limit = min(int(os.environ.get("M3MX_PROCESS_OUTPUT_BYTES", 64 * 1024**2)), 256 * 1024**2)
    total = 0
    try:
        for name in ("stdout", "stderr"):
            selector.register(getattr(proc, name), selectors.EVENT_READ, name)
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(cmd, timeout)
            for key, _ in selector.select(0.2):
                data = os.read(key.fileobj.fileno(), 16384)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                total += len(data)
                if total > limit:
                    raise ValueError("plugin output limit exceeded")
                yield key.data, data.decode("utf-8", "replace")
        proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        yield "exit", proc.returncode
    finally:
        selector.close()
        stop_process(proc)
        proc.stdout.close()
        proc.stderr.close()
