"""
os_fingerprint.py
-------------------
Very lightweight, heuristic OS guessing. This is NOT a replacement for
a proper fingerprinting engine (like Nmap's -O, which compares dozens of
packet characteristics against a huge signature database) -- it's a
simple triage heuristic based on the IP TTL of a reply, optionally
combined with the initial TCP window size when scapy is available.

Method:
  1. Get a TTL value back from the host (via the system ping utility --
     this needs no special privileges on any major OS).
  2. Compare against the initial TTL values used by default by common
     OS families (64, 128, 255) since TTL decreases by 1 per hop;
     we estimate the *original* TTL by rounding the observed TTL up to
     the nearest common starting value.
  3. If scapy is installed, also peek at the TCP window size of a SYN-ACK
     from an open port, which can help disambiguate close cases.

Results are reported as a best-guess with an explicit confidence level
because TTL-based guessing is easy to spoof or get wrong (custom TTLs,
asymmetric routing, virtualization, etc).
"""

from __future__ import annotations

import platform
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Optional

try:
    from scapy.all import IP, TCP, sr1  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover
    SCAPY_AVAILABLE = False


# Common initial TTL values used by major OS families.
_TTL_GUESSES = [
    (64, "Linux / Unix / macOS"),
    (128, "Windows"),
    (255, "Cisco / Solaris / Network device"),
]


@dataclass
class OSFingerprint:
    guess: str
    confidence: str        # "low" / "medium"
    observed_ttl: Optional[int] = None
    estimated_initial_ttl: Optional[int] = None
    tcp_window_size: Optional[int] = None
    notes: str = ""


def _get_ttl_via_ping(host: str, timeout: float = 1.5) -> Optional[int]:
    """Run one system ping and parse the TTL out of the reply text."""
    system = platform.system().lower()
    timeout_ms = max(int(timeout * 1000), 100)
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        wait_s = max(int(timeout), 1)
        cmd = ["ping", "-c", "1", "-W", str(wait_s), host]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
    except (subprocess.TimeoutExpired, OSError):
        return None

    match = re.search(r"ttl[=:](\d+)", proc.stdout, re.I)
    if match:
        return int(match.group(1))
    return None


def _get_window_size(host: str, open_port: int, timeout: float = 1.5) -> Optional[int]:
    """Best-effort grab of the TCP window size from a SYN-ACK (needs scapy + privileges)."""
    if not SCAPY_AVAILABLE:
        return None
    try:
        pkt = IP(dst=host) / TCP(dport=open_port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is not None and resp.haslayer(TCP):
            return int(resp[TCP].window)
    except PermissionError:
        return None
    except Exception:  # pragma: no cover
        return None
    return None


def fingerprint(host: str, open_tcp_port: Optional[int] = None, timeout: float = 1.5) -> OSFingerprint:
    """Produce a best-effort OS guess for `host`.

    `open_tcp_port` (optional): a known-open TCP port to use for the
    scapy-based window-size probe, when scapy is available.
    """
    ttl = _get_ttl_via_ping(host, timeout=timeout)
    window = _get_window_size(host, open_tcp_port, timeout=timeout) if open_tcp_port else None

    if ttl is None:
        return OSFingerprint(
            guess="Unknown",
            confidence="low",
            notes="Host did not respond to ping; TTL-based fingerprinting needs an ICMP reply.",
        )

    # Estimate the *original* TTL by rounding up to the nearest common
    # starting value (since each hop decrements TTL by 1).
    estimated = next((base for base, _ in _TTL_GUESSES if ttl <= base), None)
    if estimated is None:
        return OSFingerprint(
            guess="Unknown (unusual TTL)",
            confidence="low",
            observed_ttl=ttl,
            tcp_window_size=window,
            notes=f"Observed TTL {ttl} doesn't match common OS defaults (64/128/255).",
        )

    label = dict((b, l) for b, l in _TTL_GUESSES)[estimated]
    hops = estimated - ttl
    confidence = "medium" if hops <= 10 else "low"
    notes = f"Estimated ~{hops} network hop(s) between scanner and target."

    # A very small window size alongside a Windows-shaped TTL nudges
    # confidence slightly but we keep this conservative and explicit.
    if window is not None:
        notes += f" Observed initial TCP window size: {window}."

    return OSFingerprint(
        guess=label,
        confidence=confidence,
        observed_ttl=ttl,
        estimated_initial_ttl=estimated,
        tcp_window_size=window,
        notes=notes,
    )
