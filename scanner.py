"""
scanner.py
----------
Network probing logic with three scan strategies:

- TCP connect scan (-sT): normal socket.connect(), no privileges, default.
- UDP scan (-sU): sends a probe and classifies based on response / ICMP.
- SYN / half-open scan (-sS): requires scapy + raw-socket privileges;
  falls back to TCP connect and warns the caller.

Upgrades over v1:
  - IPv6 auto-detection (AF_INET6 when host resolves to an IPv6 address).
  - Configurable per-port retry count for unreliable links.
  - More precise errno → state mapping (ETIMEDOUT, ENETUNREACH, etc.).
  - Optional source-port randomisation in SYN scans.
  - Scan-type preserved correctly on fallback paths.
"""

from __future__ import annotations

import errno
import random
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

from .ports_data import get_service_name

# ---------------------------------------------------------------------------
# Optional scapy import (SYN scan / OS fingerprint only)
# ---------------------------------------------------------------------------
try:
    from scapy.all import IP, IPv6, TCP, sr1  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover
    SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Port state constants
# ---------------------------------------------------------------------------
OPEN           = "open"
CLOSED         = "closed"
FILTERED       = "filtered"
OPEN_FILTERED  = "open|filtered"
ERROR          = "error"

# errno codes that mean the port is definitively closed (connection refused)
_REFUSED = frozenset({errno.ECONNREFUSED})

# errno codes that indicate the network path is broken / filtered
_UNREACHABLE = frozenset({
    getattr(errno, "EHOSTUNREACH", None),
    getattr(errno, "ENETUNREACH",  None),
    getattr(errno, "ETIMEDOUT",    None),
    getattr(errno, "EACCES",       None),   # some BSDs use this for filtered
})
_UNREACHABLE -= {None}  # in case an attr doesn't exist on the platform


@dataclass
class ScanResult:
    host: str
    port: int
    protocol: str             # "tcp" or "udp"
    state: str                # open / closed / filtered / open|filtered / error
    service: str = ""
    banner: str = ""
    response_time_ms: Optional[float] = None
    error: Optional[str] = None
    scan_type: str = "connect"  # connect / syn / udp / connect-fallback

    def __post_init__(self) -> None:
        if not self.service:
            self.service = get_service_name(self.port)


def _resolve_family(host: str) -> int:
    """Return AF_INET6 if the host resolves to an IPv6 address, else AF_INET."""
    try:
        info = socket.getaddrinfo(host, None)
        for fam, *_ in info:
            if fam == socket.AF_INET6:
                return socket.AF_INET6
    except OSError:
        pass
    return socket.AF_INET


class ScanEngine:
    """Shared scan configuration and one probe method per protocol."""

    def __init__(
        self,
        timeout: float = 1.0,
        delay: float = 0.0,
        retries: int = 0,
    ) -> None:
        self.timeout = timeout
        self.delay = delay      # seconds between probes (rate limiting)
        self.retries = retries  # retry count for TCP connect on timeout

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sleep(self) -> None:
        if self.delay:
            time.sleep(self.delay)

    def _make_tcp_socket(self, family: int) -> socket.socket:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        return sock

    # ------------------------------------------------------------------
    # TCP connect scan
    # ------------------------------------------------------------------

    def tcp_connect_scan(self, host: str, port: int) -> ScanResult:
        self._sleep()
        family = _resolve_family(host)
        attempts = max(self.retries, 0) + 1

        for attempt in range(attempts):
            sock = self._make_tcp_socket(family)
            start = time.perf_counter()
            try:
                rc = sock.connect_ex((host, port))
                elapsed = (time.perf_counter() - start) * 1000

                if rc == 0:
                    return ScanResult(
                        host, port, "tcp", OPEN,
                        response_time_ms=elapsed, scan_type="connect"
                    )
                if rc in _REFUSED:
                    return ScanResult(
                        host, port, "tcp", CLOSED,
                        response_time_ms=elapsed, scan_type="connect"
                    )
                if rc in _UNREACHABLE:
                    # Don't retry on hard network errors
                    return ScanResult(
                        host, port, "tcp", FILTERED,
                        response_time_ms=elapsed, scan_type="connect"
                    )
                # Catch-all (EWOULDBLOCK on non-blocking, etc.)
                if attempt < attempts - 1:
                    continue
                return ScanResult(
                    host, port, "tcp", FILTERED,
                    response_time_ms=elapsed, scan_type="connect"
                )

            except socket.timeout:
                elapsed = (time.perf_counter() - start) * 1000
                if attempt < attempts - 1:
                    continue
                return ScanResult(
                    host, port, "tcp", FILTERED,
                    response_time_ms=elapsed, scan_type="connect"
                )
            except PermissionError as exc:
                return ScanResult(
                    host, port, "tcp", ERROR,
                    error=f"Permission denied: {exc}", scan_type="connect"
                )
            except OSError as exc:
                err_no = getattr(exc, "errno", None)
                if err_no in _REFUSED:
                    return ScanResult(host, port, "tcp", CLOSED, scan_type="connect")
                return ScanResult(
                    host, port, "tcp", ERROR,
                    error=str(exc), scan_type="connect"
                )
            finally:
                sock.close()

        # Should not reach here, but be defensive
        return ScanResult(host, port, "tcp", FILTERED, scan_type="connect")

    # ------------------------------------------------------------------
    # UDP scan
    # ------------------------------------------------------------------

    def udp_scan(self, host: str, port: int) -> ScanResult:
        self._sleep()
        family = _resolve_family(host)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        start = time.perf_counter()

        try:
            # Empty probe triggers ICMP port-unreachable on closed UDP ports.
            sock.sendto(b"\x00", (host, port))
            try:
                data, _ = sock.recvfrom(2048)
                elapsed = (time.perf_counter() - start) * 1000
                banner = data[:256].decode(errors="replace") if data else ""
                return ScanResult(
                    host, port, "udp", OPEN,
                    banner=banner, response_time_ms=elapsed, scan_type="udp"
                )
            except socket.timeout:
                # No response: open (silently drops probe) OR filtered.
                return ScanResult(
                    host, port, "udp", OPEN_FILTERED,
                    response_time_ms=(time.perf_counter() - start) * 1000,
                    scan_type="udp"
                )
            except ConnectionResetError:
                # ICMP port-unreachable surfaced as connection reset on Windows.
                return ScanResult(
                    host, port, "udp", CLOSED,
                    response_time_ms=(time.perf_counter() - start) * 1000,
                    scan_type="udp"
                )
            except OSError as exc:
                err_no = getattr(exc, "errno", None)
                if err_no in _REFUSED:
                    return ScanResult(
                        host, port, "udp", CLOSED,
                        response_time_ms=(time.perf_counter() - start) * 1000,
                        scan_type="udp"
                    )
                return ScanResult(host, port, "udp", ERROR, error=str(exc), scan_type="udp")

        except OSError as exc:
            return ScanResult(host, port, "udp", ERROR, error=str(exc), scan_type="udp")
        finally:
            sock.close()

    # ------------------------------------------------------------------
    # SYN (half-open) scan — requires scapy + raw socket privileges
    # ------------------------------------------------------------------

    def syn_scan(self, host: str, port: int) -> ScanResult:
        if not SCAPY_AVAILABLE:
            result = self.tcp_connect_scan(host, port)
            result.scan_type = "connect-fallback"
            result.error = "scapy not installed; fell back to TCP connect"
            return result

        self._sleep()
        start = time.perf_counter()

        # Randomise source port to reduce collision probability on busy hosts.
        src_port = random.randint(49152, 65535)

        try:
            # Detect IPv6 and build the appropriate packet.
            family = _resolve_family(host)
            if family == socket.AF_INET6:
                pkt = IPv6(dst=host) / TCP(sport=src_port, dport=port, flags="S")
            else:
                pkt = IP(dst=host) / TCP(sport=src_port, dport=port, flags="S")

            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            elapsed = (time.perf_counter() - start) * 1000

            if resp is None:
                return ScanResult(host, port, "tcp", FILTERED,
                                  response_time_ms=elapsed, scan_type="syn")

            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags & 0x12 == 0x12:  # SYN-ACK → open
                    # Send RST to cleanly close the half-open connection.
                    if family == socket.AF_INET6:
                        rst = IPv6(dst=host) / TCP(
                            sport=src_port, dport=port, flags="R",
                            seq=resp[TCP].ack
                        )
                    else:
                        rst = IP(dst=host) / TCP(
                            sport=src_port, dport=port, flags="R",
                            seq=resp[TCP].ack
                        )
                    sr1(rst, timeout=self.timeout, verbose=0)
                    return ScanResult(host, port, "tcp", OPEN,
                                      response_time_ms=elapsed, scan_type="syn")

                if flags & 0x04:  # RST flag set → closed
                    return ScanResult(host, port, "tcp", CLOSED,
                                      response_time_ms=elapsed, scan_type="syn")

            # ICMP unreachable or unexpected packet → filtered
            return ScanResult(host, port, "tcp", FILTERED,
                              response_time_ms=elapsed, scan_type="syn")

        except PermissionError as exc:
            result = self.tcp_connect_scan(host, port)
            result.scan_type = "connect-fallback"
            result.error = (
                f"SYN scan needs elevated privileges ({exc}); "
                "used TCP connect instead"
            )
            return result
        except Exception as exc:  # pragma: no cover
            return ScanResult(host, port, "tcp", ERROR,
                              error=str(exc), scan_type="syn")
