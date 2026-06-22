"""
profiles.py
-----------
Save and load named scan profiles so common scan configurations can be
reused without retyping all flags each time.

Profiles are stored as JSON files in ~/.port_scanner/profiles/.

Upgrades over v1:
  - Profile schema versioning (catches outdated saved profiles).
  - Profile deletion (delete_profile).
  - validate_profile() warns about unknown keys rather than silently ignoring.
  - Sanitises profile names to prevent directory traversal.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List

PROFILE_DIR = Path.home() / ".port_scanner" / "profiles"
SCHEMA_VERSION = 2

# Keys serialised from argparse.Namespace that make sense to store.
_SERIALISABLE_KEYS = {
    "ports", "top_ports", "exclude_ports", "exclude_hosts",
    "scan_type", "threads", "timeout", "delay", "retries",
    "service_detection", "os_detection", "ping_sweep",
    "verbose", "output_json", "output_csv", "output_txt",
    "output_html", "output_xml",
}


class ProfileError(ValueError):
    """Raised when a profile file is corrupt or incompatible."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save_profile(name: str, args: argparse.Namespace) -> str:
    """
    Serialise the relevant flags from *args* and write them to a named profile.
    Returns the profile file path as a string.
    """
    _validate_name(name)
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)

    payload: Dict[str, Any] = {"_schema_version": SCHEMA_VERSION}
    for key in _SERIALISABLE_KEYS:
        value = getattr(args, key, None)
        if value is not None and value is not False:
            payload[key] = value

    path = PROFILE_DIR / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def load_profile(name: str) -> Dict[str, Any]:
    """
    Load a named profile and return its contents as a dict.

    Raises FileNotFoundError if the profile doesn't exist.
    Raises ProfileError if the file is corrupt or has an incompatible schema.
    """
    _validate_name(name)
    path = PROFILE_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"Profile {name!r} not found. "
            f"Use --save-profile to create it, or --list-profiles to see what's available."
        )

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProfileError(f"Profile {name!r} is not valid JSON: {exc}") from exc

    version = data.pop("_schema_version", 1)
    if version > SCHEMA_VERSION:
        raise ProfileError(
            f"Profile {name!r} was created with a newer version of this tool "
            f"(schema v{version}). Please upgrade."
        )

    # Warn about unknown keys (forward-compatibility noise, not fatal).
    unknown = set(data.keys()) - _SERIALISABLE_KEYS
    if unknown:
        import warnings
        warnings.warn(
            f"Profile {name!r} contains unknown keys (ignored): {sorted(unknown)}",
            stacklevel=2,
        )

    return {k: v for k, v in data.items() if k in _SERIALISABLE_KEYS}


def list_profiles() -> List[str]:
    """Return a sorted list of saved profile names (without the .json suffix)."""
    if not PROFILE_DIR.exists():
        return []
    return sorted(
        p.stem for p in PROFILE_DIR.glob("*.json") if p.is_file()
    )


def delete_profile(name: str) -> bool:
    """
    Delete a named profile.  Returns True if deleted, False if not found.
    """
    _validate_name(name)
    path = PROFILE_DIR / f"{name}.json"
    if path.exists():
        path.unlink()
        return True
    return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


def _validate_name(name: str) -> None:
    if not _SAFE_NAME_RE.match(name):
        raise ValueError(
            f"Invalid profile name {name!r}. "
            "Use only letters, digits, hyphens, and underscores (max 64 chars)."
        )
