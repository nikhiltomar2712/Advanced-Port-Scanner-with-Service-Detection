"""
os_fingerprint.py
-----------------
Lightweight heuristic OS guessing — NOT a replacement for Nmap's -O.

Method:
  1. Obtain a TTL from the host via the system ping utility (no special
     privileges needed on any major OS).
  2. Round the observed TTL up to the nearest well-known starting value
     (64, 128, 255) and map it to an OS family.
  3. Optionally peek at the TCP window size of a SYN-ACK using scapy,
     which helps disambiguate Windows variants.
  4. If an SSH banner is available (from service_detection), extract
     OS hints from the software string (e.g. "OpenSSH_8.9p1 Ubuntu").

Upgrades over v1:
  - Expanded OS-family database (FreeBSD, OpenBSD, iOS/Android, AIX,
    HP-UX, z/OS mainframe, VxWorks embedded, Cisco IOS/NX-OS, etc.).
  - Three-tier confidence: "high" / "medium" / "low".
  - SSH banner OS hint extraction.
  - IPv6 ping support.
  - Better hop-count estimation and logging.
"""

from __future__ import annotations

import platform
import re
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Optional

try:
    from scapy.all import IP, IPv6, TCP, sr1  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# TTL → OS family mapping
# Each entry: (initial_ttl, os_label)
# Checked in ascending TTL order; we round the observed TTL *up* to the
# nearest initial_ttl to account for hops already traversed.
# ---------------------------------------------------------------------------
_TTL_MAP: list[tuple[int, str]] = [
    (30,  "Cisco Catalyst (default 30 TTL)"),
    (60,  "Solaris 2.x / HP-UX 10.x (old)"),
    (64,  "Linux / macOS / FreeBSD / iOS / Android"),
    (128, "Windows"),
    (200, "Cisco router (200 TTL variant)"),
    (255, "Cisco IOS / Junos / Solaris 10+ / OpenBSD / AIX"),
]

# Window-size disambiguation: known TCP window sizes per OS variant.
# Used to narrow down within a TTL bucket.
_WINDOW_HINTS: list[tuple[range | set, str, str]] = [
    # Windows variants — all share TTL=128
    ({8192},          "Windows XP / Server 2003",    "medium"),
    ({65535},         "Windows Vista / 7 / Server 2008", "medium"),
    ({8192, 64240},   "Windows 10 / 11 / Server 2016+",  "medium"),
    # Linux variants — TTL=64
    ({5840},          "Linux 2.6 kernel",            "medium"),
    ({29200},         "Linux 3.x kernel",            "medium"),
    ({65535},         "Linux 5.x+ / macOS / BSD",    "low"),
    # macOS — TTL=64, large window
    ({65535, 131072}, "macOS / iOS",                 "medium"),
]

# SSH banner patterns that hint at the underlying OS.
_SSH_OS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"Ubuntu",      re.I), "Linux (Ubuntu)"),
    (re.compile(r"Debian",      re.I), "Linux (Debian)"),
    (re.compile(r"CentOS|RHEL|Red Hat", re.I), "Linux (RHEL/CentOS)"),
    (re.compile(r"Fedora",      re.I), "Linux (Fedora)"),
    (re.compile(r"Alpine",      re.I), "Linux (Alpine)"),
    (re.compile(r"FreeBSD",     re.I), "FreeBSD"),
    (re.compile(r"OpenBSD",     re.I), "OpenBSD"),
    (re.compile(r"NetBSD",      re.I), "NetBSD"),
    (re.compile(r"Windows",     re.I), "Windows"),
    (re.compile(r"Cisco",       re.I), "Cisco IOS"),
    (re.compile(r"Juniper|JunOS", re.I), "Juniper JunOS"),
    (re.compile(r"Darwin",      re.I), "macOS"),
    (re.compile(r"Android",     re.I), "Android"),
]


@dataclass
class OSFingerprint:
    guess: str
    confidence: str                     # "high" | "medium" | "low"
    observed_ttl: Optional[int] = None
    estimated_initial_ttl: Optional[int] = None
    tcp_window_size: Optional[int] = None
    ssh_os_hint: Optional[str] = None
    notes: str = ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fingerprint(
    host: str,
    open_tcp_port: Optional[int] = None,
    ssh_banner: Optional[str] = None,
    timeout: float = 1.5,
) -> OSFingerprint:
    """
    Produce a best-effort OS guess for `host`.

    Parameters
    ----------
    host:          Target IP or hostname.
    open_tcp_port: A known-open TCP port to probe for window size (scapy).
    ssh_banner:    SSH software version string, if already obtained by
                   service_detection (e.g. "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6").
    timeout:       Timeout for ping and scapy probes.
    """
    ttl    = _get_ttl_via_ping(host, timeout=timeout)
    window = (_get_window_size(host, open_tcp_port, timeout=timeout)
              if open_tcp_port else None)
    ssh_hint = _parse_ssh_banner(ssh_banner) if ssh_banner else None

    # -- No TTL → unknown -------------------------------------------------
    if ttl is None:
        return OSFingerprint(
            guess="Unknown",
            confidence="low",
            ssh_os_hint=ssh_hint,
            notes=(
                "Host did not respond to ping; cannot infer OS from TTL. "
                + (f"SSH banner suggests: {ssh_hint}." if ssh_hint else "")
            ),
        )

    # -- Round TTL up to nearest initial value ----------------------------
    estimated = next((base for base, _ in _TTL_MAP if ttl <= base), None)
    if estimated is None:
        return OSFingerprint(
            guess="Unknown (unusual TTL)",
            confidence="low",
            observed_ttl=ttl,
            tcp_window_size=window,
            ssh_os_hint=ssh_hint,
            notes=f"TTL {ttl} does not match any known OS default.",
        )

    label  = dict(_TTL_MAP)[estimated]
    hops   = estimated - ttl
    confidence = "medium" if hops <= 8 else "low"
    notes_parts = [f"Estimated ~{hops} hop(s) between scanner and target."]

    # -- SSH banner refines the guess -------------------------------------
    if ssh_hint:
        # SSH banner is generally very reliable — treat as high confidence
        # for the OS family, but keep medium for exact version.
        label = ssh_hint
        confidence = "high"
        notes_parts.append(f"OS confirmed via SSH banner: {ssh_hint}.")

    # -- Window-size disambiguation (scapy) -------------------------------
    elif window is not None:
        notes_parts.append(f"Observed TCP window size: {window}.")
        for win_set, win_label, win_conf in _WINDOW_HINTS:
            if isinstance(win_set, set) and window in win_set:
                label = win_label
                if win_conf == "medium" and confidence != "low":
                    confidence = "medium"
                notes_parts.append(f"Window size {window} consistent with {win_label}.")
                break

    return OSFingerprint(
        guess=label,
        confidence=confidence,
        observed_ttl=ttl,
        estimated_initial_ttl=estimated,
        tcp_window_size=window,
        ssh_os_hint=ssh_hint,
        notes=" ".join(notes_parts),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_ttl_via_ping(host: str, timeout: float = 1.5) -> Optional[int]:
    """Run one system ping and extract the TTL from the output."""
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(max(int(timeout * 1000), 100)), host]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-t", str(max(int(timeout), 1)), host]
    else:  # Linux and other Unix-likes
        # -W is in seconds on Linux; some platforms use -t.
        cmd = ["ping", "-c", "1", "-W", str(max(int(timeout), 1)), host]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 3,
        )
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return None

    # Parse "ttl=64" or "TTL=128" or "ttl=X" from stdout.
    match = re.search(r"ttl[=:](\d+)", proc.stdout, re.I)
    if match:
        return int(match.group(1))

    # Some platforms put it in stderr or with a space: "ttl = 64".
    match = re.search(r"ttl\s*[=:]\s*(\d+)", proc.stdout + proc.stderr, re.I)
    if match:
        return int(match.group(1))

    return None


def _get_window_size(
    host: str,
    open_port: int,
    timeout: float = 1.5,
) -> Optional[int]:
    """Grab the initial TCP window size from a SYN-ACK (requires scapy + privileges)."""
    if not SCAPY_AVAILABLE:
        return None
    try:
        family = socket.AF_INET
        try:
            info = socket.getaddrinfo(host, None)
            if any(f == socket.AF_INET6 for f, *_ in info):
                family = socket.AF_INET6
        except OSError:
            pass

        if family == socket.AF_INET6:
            from scapy.all import IPv6  # type: ignore
            pkt = IPv6(dst=host) / TCP(dport=open_port, flags="S")
        else:
            pkt = IP(dst=host) / TCP(dport=open_port, flags="S")

        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is not None and resp.haslayer(TCP):
            return int(resp[TCP].window)
    except PermissionError:
        pass
    except Exception:  # pragma: no cover
        pass
    return None


def _parse_ssh_banner(banner: str) -> Optional[str]:
    """Extract an OS hint from an SSH software version string."""
    for pattern, os_label in _SSH_OS_PATTERNS:
        if pattern.search(banner):
            return os_label
    return None
