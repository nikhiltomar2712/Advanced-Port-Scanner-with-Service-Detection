"""
service_detection.py
---------------------
Best-effort service/version identification for ports that the scanner
found open. Two strategies are combined:

  1. Passive banner read: just connect and see if the service announces
     itself immediately (SSH, FTP, SMTP, and many others do this).
  2. Active probe: for protocols that wait for the client to speak first
     (HTTP, etc.) we send a minimal, harmless probe request and read
     whatever comes back.

Everything here is regex-based pattern matching over plaintext banners --
no exploitation, no fuzzing, no protocol abuse. This mirrors what any
basic banner-grabbing tool (e.g. `nc host port`, `curl -I`) would do
manually, just automated and applied across many ports.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from typing import Optional

# Ports where the server speaks first -- just read.
_PASSIVE_BANNER_PORTS = {21, 22, 23, 25, 110, 143, 220, 587}

# Minimal, standard, non-destructive probes for protocols that wait for
# the client. These are exactly what a normal client would send.
_ACTIVE_PROBES = {
    80: b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: PortScanner/1.0\r\n\r\n",
    3306: b"",          # MySQL sends a greeting on connect; no probe needed
    6379: b"PING\r\n",  # Redis
    27017: b"",         # MongoDB -- mostly relies on passive read
}

# (regex, service, version-group-index-or-None) -- checked in order
_SIGNATURES = [
    (re.compile(rb"^SSH-([\d.]+)-(\S+)"), "ssh", 2),
    (re.compile(rb"^220.*?FTP", re.I), "ftp", None),
    (re.compile(rb"^220.*?ESMTP\s+(\S+)", re.I), "smtp", 1),
    (re.compile(rb"^220.*?SMTP", re.I), "smtp", None),
    (re.compile(rb"^\+OK.*?POP3", re.I), "pop3", None),
    (re.compile(rb"^\*\s*OK.*?IMAP", re.I), "imap", None),
    (re.compile(rb"HTTP/\d\.\d\s+\d+"), "http", None),
    (re.compile(rb"^-ERR|^\+PONG", re.I), "redis", None),
    (re.compile(rb"^[\x00-\x09]\x00\x00\x00.{0,4}mysql_native_password|mysql", re.I), "mysql", None),
    (re.compile(rb"^\x00\x00\x00.{0,8}ismaster", re.I), "mongodb", None),
]

_SERVER_HEADER_RE = re.compile(rb"Server:\s*(.+)", re.I)


@dataclass
class ServiceInfo:
    service: str
    banner: str
    version: Optional[str] = None


def grab_banner(host: str, port: int, timeout: float = 2.0) -> ServiceInfo:
    """Attempt to read a banner / fingerprint the service on an open TCP port.

    Returns a ServiceInfo with empty fields if nothing could be read --
    this is normal for many services and not treated as an error.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    raw = b""
    try:
        sock.connect((host, port))

        if port in _ACTIVE_PROBES:
            probe = _ACTIVE_PROBES[port].replace(b"%HOST%", host.encode())
            if probe:
                sock.sendall(probe)
        # Passive ports and "no probe needed" active ports both just read.
        try:
            raw = sock.recv(2048)
        except socket.timeout:
            raw = b""
    except (socket.timeout, ConnectionRefusedError, OSError):
        raw = b""
    finally:
        sock.close()

    return _classify(raw, port)


def _classify(raw: bytes, port: int) -> ServiceInfo:
    banner_text = raw[:512].decode(errors="replace").strip()

    for pattern, service, version_group in _SIGNATURES:
        match = pattern.search(raw)
        if match:
            version = None
            if version_group is not None:
                try:
                    version = match.group(version_group).decode(errors="replace")
                except (IndexError, AttributeError):
                    version = None
            return ServiceInfo(service=service, banner=banner_text, version=version)

    # HTTP responses often carry the version in a Server: header even if
    # the status-line signature above already matched generically.
    server_match = _SERVER_HEADER_RE.search(raw)
    if server_match:
        server_value = server_match.group(1).decode(errors="replace").split("\r")[0].strip()
        return ServiceInfo(service="http", banner=banner_text, version=server_value)

    return ServiceInfo(service="", banner=banner_text, version=None)
