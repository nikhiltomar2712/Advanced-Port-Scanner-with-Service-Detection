"""
profiles.py
------------
Lets users save the CLI options of a scan as a named "profile" and
reload it later instead of retyping a long command. Profiles are stored
as plain JSON in ~/.port_scanner/profiles/<name>.json.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

PROFILE_DIR = Path.home() / ".port_scanner" / "profiles"

# Only these argparse destinations are persisted -- deliberately excludes
# things like --load-profile itself to avoid recursive nonsense.
_SAVED_KEYS = [
    "target", "ports", "top_ports", "scan_type", "threads", "timeout",
    "delay", "service_detection", "os_detection", "ping_sweep", "verbose",
    "output_json", "output_csv", "output_txt", "output_html",
]


def save_profile(name: str, args_namespace) -> Path:
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    data: Dict[str, Any] = {}
    for key in _SAVED_KEYS:
        if hasattr(args_namespace, key):
            data[key] = getattr(args_namespace, key)
    path = PROFILE_DIR / f"{name}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def load_profile(name: str) -> Dict[str, Any]:
    path = PROFILE_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"No saved profile named '{name}' in {PROFILE_DIR}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_profiles() -> list[str]:
    if not PROFILE_DIR.exists():
        return []
    return sorted(p.stem for p in PROFILE_DIR.glob("*.json"))
