"""Stable evidence identities and immutable directories for analysis runs."""
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import uuid

from .config import ROOT, safe_output_dir
from .security import checked_path
from .storage import write_json


def image_identity(image) -> tuple:
    path = Path(image).resolve()
    st = path.stat()
    return str(path), st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def evidence_key(image) -> str:
    path = Path(image).resolve()
    if re.fullmatch(r"[0-9a-f]{32}", path.parent.name):
        identity = path.parent.name
    else:
        identity = hashlib.sha256(repr(image_identity(path)).encode()).hexdigest()[:32]
    stem = re.sub(r"[^A-Za-z0-9_-]", "_", path.stem)[:80] or "image"
    return f"{stem}_{identity}"


def _root(image) -> Path:
    return checked_path(Path(safe_output_dir()) / "full_analysis" / evidence_key(image),
                        ("output",), must_exist=False)


def case_directory(image) -> Path:
    root = _root(image)
    pointer = root / ".latest.json"
    if pointer.exists():
        latest = json.loads(pointer.read_text()).get("run_id", "")
        if re.fullmatch(r"[0-9a-f]{32}", latest):
            return checked_path(root / latest, ("output",), must_exist=False)
    # Preserve access to existing cases without silently migrating or deleting.
    legacy = Path(safe_output_dir()) / "full_analysis" / Path(image).stem
    if legacy.is_dir():
        return checked_path(legacy, ("output",))
    return root


def begin_run(image) -> Path:
    image = checked_path(image, ("evidence",), file=True)
    root = _root(image)
    run_id = uuid.uuid4().hex
    case = root / run_id
    case.mkdir(parents=True, mode=0o700)
    versions = {}
    for package in ("volatility3", "Flask", "weasyprint"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "unavailable"
    manifest = {"run_id": run_id, "evidence_key": evidence_key(image),
                "image": str(image), "image_identity": list(image_identity(image)),
                "started_at": datetime.now(timezone.utc).isoformat(), "versions": versions,
                "rule_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in sorted((ROOT / "rules").glob("*.yaml"))}}
    metadata = image.parent / "manifest.json"
    if metadata.exists():
        manifest["evidence"] = json.loads(metadata.read_text())
    write_json(case / "manifest.json", manifest)
    write_json(root / ".latest.json", {"run_id": run_id})
    return case
