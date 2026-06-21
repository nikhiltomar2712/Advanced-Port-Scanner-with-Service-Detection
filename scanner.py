"""
scanner.py
----------
The actual network probing logic. Three scan strategies are provided:

  - TCP connect scan (-sT): uses a normal socket.connect(), works
    everywhere, no special privileges required. This is the default
    and the most reliable.

  - UDP scan (-sU): sends an (optionally protocol-aware) probe and
    classifies the port based on whether a response or an ICMP
    "port unreachable" comes back. UDP scanning is inherently slower
    and less reliable than TCP -- this is a fundamental protocol
    limitation, not a bug in this tool.

  - SYN / half-open scan (-sS): only available when scapy is installed
    AND the process has permission to send raw packets (typically
    root/Administrator). If either condition isn't met, the engine
    transparently falls back to a TCP connect scan and surfaces a
    warning to the caller so the user understands what actually ran.

All three return a uniform ScanResult so the rest of the program
doesn't need to care which strategy produced it.
"""

from __future__ import annotations

import errno
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

from .ports_data import get_service_name

# Scapy is optional. Only the SYN scan and (optionally) more detailed
# OS fingerprinting depend on it; everything else works with the
# standard library alone.
try:
    from scapy.all import IP, TCP, sr1  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    SCAPY_AVAILABLE = False


OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"
OPEN_FILTERED = "open|filtered"
ERROR = "error"


@dataclass
class ScanResult:
    host: str
    port: int
    protocol: str           # "tcp" or "udp"
    state: str               # open / closed / filtered / open|filtered / error
    service: str = ""
    banner: str = ""
    response_time_ms: Optional[float] = None
    error: Optional[str] = None
    scan_type: str = "connect"   # connect / syn / udp

    def __post_init__(self):
        if not self.service:
            self.service = get_service_name(self.port)


class ScanEngine:
    """Holds shared scan configuration and exposes one method per protocol."""

    def __init__(self, timeout: float = 1.0, delay: float = 0.0):
        self.timeout = timeout
        self.delay = delay  # seconds to sleep before each probe (rate limiting)

    # ------------------------------------------------------------------ #
    # TCP connect scan
    # ------------------------------------------------------------------ #
    def tcp_connect_scan(self, host: str, port: int) -> ScanResult:
        if self.delay:
            time.sleep(self.delay)

        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result_code = sock.connect_ex((host, port))
            elapsed_ms = (time.time() - start) * 1000
            if result_code == 0:
                state = OPEN
            elif result_code in (errno.ECONNREFUSED,):
                state = CLOSED
            else:
                # timeout, host unreachable, etc -> treated as filtered
                state = FILTERED
            return ScanResult(host, port, "tcp", state, response_time_ms=elapsed_ms,
                               scan_type="connect")
        except socket.timeout:
            return ScanResult(host, port, "tcp", FILTERED,
                               response_time_ms=(time.time() - start) * 1000,
                               scan_type="connect")
        except PermissionError as exc:
            return ScanResult(host, port, "tcp", ERROR, error=f"Permission denied: {exc}")
        except OSError as exc:
            return ScanResult(host, port, "tcp", ERROR, error=str(exc))
        finally:
            sock.close()

    # ------------------------------------------------------------------ #
    # UDP scan
    # ------------------------------------------------------------------ #
    def udp_scan(self, host: str, port: int) -> ScanResult:
        if self.delay:
            time.sleep(self.delay)

        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            # An empty/generic probe is enough to elicit ICMP unreachable
            # from closed ports on most stacks; service_detection.py
            # sends smarter, protocol-specific probes for banner grabbing.
            sock.sendto(b"\x00", (host, port))
            try:
                data, _ = sock.recvfrom(1024)
                elapsed_ms = (time.time() - start) * 1000
                banner = data[:256].decode(errors="replace") if data else ""
                return ScanResult(host, port, "udp", OPEN, banner=banner,
                                   response_time_ms=elapsed_ms, scan_type="udp")
            except socket.timeout:
                # No response at all: could be open (silently dropping our
                # probe) or filtered by a firewall. UDP can't tell these
                # apart without a protocol-specific probe, so we report
                # the standard nmap-style ambiguous state.
                return ScanResult(host, port, "udp", OPEN_FILTERED,
                                   response_time_ms=(time.time() - start) * 1000,
                                   scan_type="udp")
        except ConnectionResetError:
            # On some platforms a previous ICMP port-unreachable surfaces
            # here as a connection reset -- treat it as definitively closed.
            return ScanResult(host, port, "udp", CLOSED,
                               response_time_ms=(time.time() - start) * 1000,
                               scan_type="udp")
        except OSError as exc:
            # ICMP port unreachable typically raises ECONNREFUSED here
            if getattr(exc, "errno", None) == errno.ECONNREFUSED:
                return ScanResult(host, port, "udp", CLOSED,
                                   response_time_ms=(time.time() - start) * 1000,
                                   scan_type="udp")
            return ScanResult(host, port, "udp", ERROR, error=str(exc))
        finally:
            sock.close()

    # ------------------------------------------------------------------ #
    # SYN (half-open) scan -- requires scapy + raw socket privileges
    # ------------------------------------------------------------------ #
    def syn_scan(self, host: str, port: int) -> ScanResult:
        if not SCAPY_AVAILABLE:
            result = self.tcp_connect_scan(host, port)
            result.scan_type = "connect-fallback"
            result.error = "scapy not installed; fell back to TCP connect scan"
            return result

        if self.delay:
            time.sleep(self.delay)

        start = time.time()
        try:
            src_port = 40000 + (port % 20000)
            pkt = IP(dst=host) / TCP(sport=src_port, dport=port, flags="S")
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            elapsed_ms = (time.time() - start) * 1000

            if resp is None:
                return ScanResult(host, port, "tcp", FILTERED,
                                   response_time_ms=elapsed_ms, scan_type="syn")

            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags & 0x12 == 0x12:  # SYN+ACK
                    # Politely tear down the half-open connection.
                    rst = IP(dst=host) / TCP(sport=src_port, dport=port, flags="R",
                                              seq=resp[TCP].ack)
                    sr1(rst, timeout=self.timeout, verbose=0)
                    return ScanResult(host, port, "tcp", OPEN,
                                       response_time_ms=elapsed_ms, scan_type="syn")
                if flags & 0x14 == 0x14:  # RST+ACK
                    return ScanResult(host, port, "tcp", CLOSED,
                                       response_time_ms=elapsed_ms, scan_type="syn")
            return ScanResult(host, port, "tcp", FILTERED,
                               response_time_ms=elapsed_ms, scan_type="syn")
        except PermissionError as exc:
            result = self.tcp_connect_scan(host, port)
            result.scan_type = "connect-fallback"
            result.error = f"SYN scan needs elevated privileges ({exc}); used TCP connect instead"
            return result
        except Exception as exc:  # pragma: no cover - network/env dependent
            return ScanResult(host, port, "tcp", ERROR, error=str(exc), scan_type="syn")
