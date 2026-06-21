"""
network_utils.py
-----------------
Helpers for turning user-supplied CLI strings into concrete lists of
targets and ports, plus a lightweight ping-sweep used for optional
host discovery before scanning.

Nothing in this module requires third-party packages.
"""

from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List

from .ports_data import TOP_100_PORTS, TOP_1000_PORTS


class TargetParseError(ValueError):
    """Raised when a target spec can't be understood."""


class PortParseError(ValueError):
    """Raised when a port spec can't be understood."""


def resolve_hostname(host: str) -> str:
    """Resolve a hostname to an IPv4/IPv6 address string.

    Raises socket.gaierror if resolution fails (left to the caller to
    handle/report, since that's a meaningful user-facing error).
    """
    return socket.gethostbyname(host)


def parse_targets(target_spec: str) -> List[str]:
    """Expand a target specification into a list of individual IPs.

    Accepts:
      - a single IP address:        "192.168.1.10"
      - a hostname:                 "example.com"
      - CIDR notation:               "192.168.1.0/28"
      - a short dash range on the last octet: "192.168.1.1-20"
      - a comma separated list of any of the above: "10.0.0.1,10.0.0.2"
    """
    targets: List[str] = []
    for chunk in (c.strip() for c in target_spec.split(",")):
        if not chunk:
            continue
        targets.extend(_parse_single_target_chunk(chunk))
    if not targets:
        raise TargetParseError(f"No valid targets found in '{target_spec}'")
    return targets


def _parse_single_target_chunk(chunk: str) -> List[str]:
    # CIDR notation, e.g. 192.168.1.0/24
    if "/" in chunk:
        try:
            network = ipaddress.ip_network(chunk, strict=False)
        except ValueError as exc:
            raise TargetParseError(f"Invalid CIDR range '{chunk}': {exc}") from exc
        # Skip network/broadcast addresses for typical IPv4 /x ranges,
        # but fall back to all hosts for very small or IPv6 networks.
        hosts = list(network.hosts())
        return [str(h) for h in hosts] if hosts else [str(network.network_address)]

    # Last-octet dash range, e.g. 192.168.1.1-20
    if "-" in chunk and chunk.count(".") == 3:
        base, _, end = chunk.rpartition("-")
        try:
            prefix, last_octet_str = base.rsplit(".", 1)
            start = int(last_octet_str)
            end_i = int(end)
        except (ValueError, IndexError) as exc:
            raise TargetParseError(f"Invalid IP range '{chunk}': {exc}") from exc
        if not (0 <= start <= 255 and 0 <= end_i <= 255 and start <= end_i):
            raise TargetParseError(f"Invalid IP range '{chunk}'")
        return [f"{prefix}.{i}" for i in range(start, end_i + 1)]

    # Plain IP or hostname
    try:
        ipaddress.ip_address(chunk)
        return [chunk]
    except ValueError:
        pass

    try:
        return [resolve_hostname(chunk)]
    except socket.gaierror as exc:
        raise TargetParseError(f"Could not resolve hostname '{chunk}': {exc}") from exc


def parse_ports(port_spec: str) -> List[int]:
    """Expand a port specification into a sorted list of unique ports.

    Accepts:
      - a single port:        "80"
      - a range:               "1-1024"
      - a comma list:          "22,80,443"
      - mixed:                 "22,80,1000-1010"
      - the keyword "all":     1-65535
    """
    spec = port_spec.strip().lower()
    if spec == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for chunk in (c.strip() for c in port_spec.split(",")):
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            try:
                start, end = int(start_s), int(end_s)
            except ValueError as exc:
                raise PortParseError(f"Invalid port range '{chunk}': {exc}") from exc
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise PortParseError(f"Port range '{chunk}' out of bounds (1-65535)")
            ports.update(range(start, end + 1))
        else:
            try:
                p = int(chunk)
            except ValueError as exc:
                raise PortParseError(f"Invalid port '{chunk}': {exc}") from exc
            if not (1 <= p <= 65535):
                raise PortParseError(f"Port '{chunk}' out of bounds (1-65535)")
            ports.add(p)

    if not ports:
        raise PortParseError(f"No valid ports found in '{port_spec}'")
    return sorted(ports)


def top_ports(count: int) -> List[int]:
    """Return the top N most common ports (N is rounded up to 100 or 1000)."""
    if count <= 100:
        return TOP_100_PORTS[:count] if count < 100 else list(TOP_100_PORTS)
    return list(TOP_1000_PORTS[:count])


def _ping_once(ip: str, timeout: float) -> bool:
    """Run a single OS ping (1 packet) and return True if it succeeded.

    Uses the system 'ping' binary so it works without root privileges
    on every major OS (raw ICMP sockets normally require root/admin).
    """
    system = platform.system().lower()
    timeout_ms = max(int(timeout * 1000), 100)
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # -W expects seconds on Linux, but accepts fractional on many
        # builds; round up to be safe and portable.
        wait_s = max(int(timeout) , 1)
        cmd = ["ping", "-c", "1", "-W", str(wait_s), ip]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 2
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def ping_sweep(targets: Iterable[str], timeout: float = 1.0, threads: int = 50) -> List[str]:
    """Return the subset of `targets` that responded to a ping.

    This is a best-effort host-discovery step intended to skip scanning
    hosts that are clearly down. Some hosts/firewalls silently drop ICMP,
    so a host not answering pings is not proof it's offline -- callers
    should treat this as an optimization, not ground truth.
    """
    targets = list(targets)
    alive: List[str] = []
    with ThreadPoolExecutor(max_workers=min(threads, max(len(targets), 1))) as pool:
        futures = {pool.submit(_ping_once, ip, timeout): ip for ip in targets}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    alive.append(ip)
            except Exception:
                continue
    return sorted(alive, key=lambda ip: targets.index(ip))
