"""Read-only forensic commands, with short-lived, one-use UI approvals."""
from __future__ import annotations

import secrets
import shlex
import shutil
import threading
import time

from .config import load_config, UPLOADS_DIR
from .processes import run_command
from .security import checked_path, PolicyError

_lock = threading.Lock()
_pending: dict[str, dict] = {}


def validate_command(command: str) -> list[str]:
    if not isinstance(command, str) or len(command) > 4096 or any(
            c in command for c in (";", "|", "&", "`", "$", "<", ">", "\n", "\r", "\x00")):
        raise PolicyError("shell operators and substitutions are not supported")
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise PolicyError("invalid command quoting") from exc
    if len(argv) < 2 or argv[0] not in {"strings", "file", "xxd", "sha256sum", "sha1sum", "md5sum"}:
        raise PolicyError("allowed tools: strings, file, xxd, sha256sum, sha1sum, md5sum")
    name = argv[0]
    executable = shutil.which(name)
    if not executable:
        raise PolicyError(f"{name} is not installed")
    # Exactly one regular file. No executable-specific options can introduce
    # another path, subprocess, write target, magic database, or stdin.
    target = checked_path(argv[-1], ("evidence", "output"), file=True)
    options = argv[1:-1]
    if name == "strings":
        if options and (len(options) != 2 or options[0] != "-n" or
                        not options[1].isdigit() or not 4 <= int(options[1]) <= 256):
            raise PolicyError("strings accepts only -n 4..256 and one file")
    elif name == "file":
        if options not in ([], ["-b"], ["--mime-type"], ["-b", "--mime-type"]):
            raise PolicyError("file accepts only -b and --mime-type")
    elif name == "xxd":
        if not options:
            options = ["-l", "4096"]
        if len(options) not in {2, 4} or options[0] != "-l" or not options[1].isdigit() or not 1 <= int(options[1]) <= 65536:
            raise PolicyError("xxd requires -l 1..65536 and optional -s offset")
        if len(options) == 4 and (options[2] != "-s" or not options[3].isdigit()):
            raise PolicyError("invalid xxd offset")
    elif options:
        raise PolicyError("hash tools accept one file and no options")
    return [executable, *options, str(target)]


def request_command(args: dict, ctx: dict) -> dict:
    ai = load_config().get("ai", {})
    if not ai.get("allow_shell_commands", False):
        return {"error": "command tools are disabled; enable them in Settings if needed"}
    argv = validate_command(args.get("command", ""))
    path = checked_path(argv[-1], ("evidence", "output"), file=True)
    stat = path.stat()
    timeout = max(1, min(int(args.get("timeout", 120)), int(ai.get("shell_command_timeout", 300)), 300))
    entry = {"argv": argv, "expires": time.monotonic() + 120, "timeout": timeout,
             "identity": (stat.st_ino, stat.st_size, stat.st_mtime_ns),
             "image": ctx.get("image_path")}
    with _lock:
        for key in list(_pending):
            if _pending[key]["expires"] < time.monotonic():
                del _pending[key]
        if len(_pending) >= 32:
            raise PolicyError("too many pending commands")
        approval_id = secrets.token_urlsafe(32)
        _pending[approval_id] = entry
    return {"approval_required": True, "approval_id": approval_id,
            "command": shlex.join(argv), "expires_in": 120,
            "message": "Execution requires the analyst to click Approve in the browser."}


def approve_command(approval_id: str, image: str | None) -> dict:
    with _lock:
        entry = _pending.pop(approval_id, None)
    if not entry or entry["expires"] < time.monotonic():
        raise PolicyError("command approval expired or was already used")
    if image != entry["image"] or not load_config()["ai"].get("allow_shell_commands", False):
        raise PolicyError("command context changed; request a new approval")
    argv = validate_command(shlex.join([
        entry["argv"][0].rsplit("/", 1)[-1], *entry["argv"][1:]]))
    stat = checked_path(argv[-1], ("evidence", "output"), file=True).stat()
    if (stat.st_ino, stat.st_size, stat.st_mtime_ns) != entry["identity"]:
        raise PolicyError("file changed after the command was proposed")
    result = run_command(argv, timeout=entry["timeout"], cwd=str(UPLOADS_DIR), max_bytes=64 * 1024)
    return {"command": shlex.join(argv), "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}
