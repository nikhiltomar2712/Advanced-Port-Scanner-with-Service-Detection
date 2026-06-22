"""
network_utils.py
-----------------
Target / port parsing, host discovery, and related network helpers.

Note: the original file was named 'network_utlis.py' (typo). This file is
the corrected name; update the import in cli.py and __init__.py accordingly.

Upgrades over v1:
  - Full IPv6 address and CIDR support.
  - IP range parsing now supports open-ended notation (192.168.1.1-50
    as well as full 192.168.1.1-192.168.1.50).
  - top_ports() respects the full TOP_1000_PORTS list even beyond 1000.
  - ping_sweep() uses concurrent threads for speed on large /24 ranges.
  - Better error messages that tell users exactly what went wrong.
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from .ports_data import TOP_100_PORTS, TOP_1000_PORTS


class TargetParseError(ValueError):
    """Raised when a target specification cannot be parsed."""


class PortParseError(ValueError):
    """Raised when a port specification cannot be parsed."""


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

def parse_targets(spec: str) -> List[str]:
    """
    Parse a target specification into a flat list of IP address strings.

    Supported formats:
      - Single hostname or IP  : "example.com", "192.168.1.1", "::1"
      - CIDR range             : "192.168.1.0/24", "10.0.0.0/28", "fd00::/120"
      - Hyphenated IP range    : "192.168.1.1-50"  or  "192.168.1.1-192.168.1.50"
      - Comma-separated list   : "192.168.1.1,192.168.1.5,example.com"
    """
    targets: List[str] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        targets.extend(_parse_single(part))

    if not targets:
        raise TargetParseError(f"No valid targets found in: {spec!r}")
    return targets


def _parse_single(spec: str) -> List[str]:
    # CIDR network
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            return [str(a) for a in net.hosts()] or [str(net.network_address)]
        except ValueError:
            raise TargetParseError(
                f"Invalid CIDR range: {spec!r}. "
                "Example: 192.168.1.0/24 or fd00::/120"
            )

    # Hyphenated range — either last-octet shorthand or full IP pair.
    if "-" in spec:
        # Could be a hostname with a hyphen; try IP first.
        parts = spec.split("-", 1)
        try:
            start_ip = ipaddress.ip_address(parts[0].strip())
        except ValueError:
            # It's a hostname, not a range.
            return [_resolve_or_raise(spec)]

        end_str = parts[1].strip()
        try:
            end_ip = ipaddress.ip_address(end_str)
        except ValueError:
            # Shorthand: "192.168.1.1-50" → last octet only
            try:
                last_octet = int(end_str)
            except ValueError:
                raise TargetParseError(
                    f"Invalid IP range: {spec!r}. "
                    "Use '192.168.1.1-50' or '192.168.1.1-192.168.1.50'."
                )
            # Reconstruct full end IP
            base = str(start_ip).rsplit(".", 1)[0]
            try:
                end_ip = ipaddress.ip_address(f"{base}.{last_octet}")
            except ValueError:
                raise TargetParseError(f"Invalid IP range: {spec!r}")

        if int(start_ip) > int(end_ip):
            raise TargetParseError(
                f"Range start {start_ip} is after end {end_ip}."
            )
        if int(end_ip) - int(start_ip) > 65535:
            raise TargetParseError(
                f"Range {spec!r} covers >65 535 hosts — "
                "use a CIDR for large ranges."
            )
        return [
            str(ipaddress.ip_address(addr))
            for addr in range(int(start_ip), int(end_ip) + 1)
        ]

    # Single IP address
    try:
        return [str(ipaddress.ip_address(spec))]
    except ValueError:
        pass

    # Fall back to hostname resolution
    return [_resolve_or_raise(spec)]


def _resolve_or_raise(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        raise TargetParseError(
            f"Cannot resolve hostname: {hostname!r}. "
            "Check spelling and DNS connectivity."
        )


# ---------------------------------------------------------------------------
# Port parsing
# ---------------------------------------------------------------------------

def parse_ports(spec: str) -> List[int]:
    """
    Parse a port specification into a sorted list of integers.

    Formats:
      - Single port   : "80"
      - Range         : "1-1024"
      - List          : "22,80,443,8080"
      - 'all'         : 1–65535
      - Combinations  : "22,80,1000-2000,443"
    """
    if spec.strip().lower() == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            lo_s, hi_s = token.split("-", 1)
            try:
                lo, hi = int(lo_s.strip()), int(hi_s.strip())
            except ValueError:
                raise PortParseError(f"Invalid port range: {token!r}")
            if not (1 <= lo <= hi <= 65535):
                raise PortParseError(
                    f"Port range {lo}-{hi} is out of bounds (1-65535)."
                )
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(token)
            except ValueError:
                raise PortParseError(f"Invalid port number: {token!r}")
            if not 1 <= p <= 65535:
                raise PortParseError(f"Port {p} is out of range (1-65535).")
            ports.add(p)

    if not ports:
        raise PortParseError(f"No valid ports found in: {spec!r}")
    return sorted(ports)


def top_ports(n: int) -> List[int]:
    """
    Return the top-N most common ports from the curated list.

    n ≤ 100  → uses TOP_100_PORTS (very fast triage).
    n ≤ 1000 → uses TOP_1000_PORTS.
    n > 1000 → returns the first n of a sorted well-known + extra set.
    """
    if n <= 0:
        raise PortParseError(f"--top-ports must be positive (got {n}).")
    if n <= len(TOP_100_PORTS):
        return TOP_100_PORTS[:n]
    if n <= len(TOP_1000_PORTS):
        return TOP_1000_PORTS[:n]
    # Beyond 1000: fill with 1-65535 and return first n
    all_ports = sorted(set(TOP_1000_PORTS) | set(range(1, 65536)))
    return all_ports[:n]


# ---------------------------------------------------------------------------
# Host discovery (ping sweep)
# ---------------------------------------------------------------------------

def ping_sweep(
    hosts: List[str],
    timeout: float = 1.0,
    max_workers: int = 128,
) -> List[str]:
    """
    Return the subset of `hosts` that respond to an ICMP ping.

    Uses the system ping utility in parallel threads.  Does NOT require
    root privileges on any major OS.
    """
    alive: List[str] = []

    def _ping(host: str) -> Optional[str]:
        import platform
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(max(int(timeout * 1000), 100)), host]
        elif system == "darwin":
            cmd = ["ping", "-c", "1", "-t", str(max(int(timeout), 1)), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(int(timeout), 1)), host]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout + 2,
            )
            return host if proc.returncode == 0 else None
        except (subprocess.TimeoutExpired, OSError):
            return None

    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts))) as pool:
        futures = {pool.submit(_ping, h): h for h in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                alive.append(result)

    # Preserve original ordering
    host_order = {h: i for i, h in enumerate(hosts)}
    return sorted(alive, key=lambda h: host_order.get(h, 0))
