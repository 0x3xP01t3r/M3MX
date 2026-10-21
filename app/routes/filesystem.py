"""Folder operations limited to operator-approved output directories."""
from pathlib import Path
import shutil
import sys

from flask import Blueprint, jsonify, request

from ..config import OUTPUTS_DIR
from ..processes import run_command
from ..security import checked_path, roots

filesystem = Blueprint("filesystem", __name__, url_prefix="/api/fs")


@filesystem.get("/browse")
def browse():
    base = checked_path(request.args.get("path") or OUTPUTS_DIR, ("output",))
    if not base.is_dir():
        return jsonify(error="not a directory"), 400
    dirs = []
    for p in sorted(base.iterdir(), key=lambda p: p.name.lower()):
        if p.is_dir() and not p.is_symlink() and not p.name.startswith("."):
            dirs.append({"name": p.name, "path": str(p)})
    parent = None if base in roots("output") else str(base.parent)
    return jsonify(path=str(base), parent=parent, dirs=dirs,
                   approved_roots=[str(p) for p in roots("output")])


@filesystem.post("/mkdir")
def mkdir():
    body = request.get_json(silent=True) or {}
    path = checked_path(body.get("path", ""), ("output",), must_exist=False)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return jsonify(ok=True, path=str(path))


@filesystem.post("/pick-dir-native")
def pick_directory():
    body = request.get_json(silent=True) or {}
    start = checked_path(body.get("start") or OUTPUTS_DIR, ("output",))
    if shutil.which("zenity"):
        cmd = ["zenity", "--file-selection", "--directory", f"--filename={start}/",
               "--title=M3MX — Select approved output directory"]
    elif shutil.which("kdialog"):
        cmd = ["kdialog", "--getexistingdirectory", str(start)]
    else:
        # Constant code; the path is an argument, never executable source.
        code = ("import tkinter as tk,sys; from tkinter import filedialog; "
                "r=tk.Tk(); r.withdraw(); "
                "print(filedialog.askdirectory(initialdir=sys.argv[1], mustexist=True) or '')")
        cmd = [sys.executable, "-c", code, str(start)]
    result = run_command(cmd, timeout=120, max_bytes=4096)
    picked = result.stdout.strip()
    if not picked or result.returncode:
        return jsonify(ok=True, cancelled=True)
    path = checked_path(picked, ("output",))
    return jsonify(ok=True, path=str(path))
