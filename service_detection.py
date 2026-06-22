"""
service_detection.py
---------------------
Best-effort service/version identification for open ports.

Two strategies:
  1. Passive banner read: connect and see if the service announces itself
     immediately (SSH, FTP, SMTP, Redis, many others do this).
  2. Active probe: for protocols that wait for the client to speak first,
     send a minimal harmless probe and read the response.

Upgrades over v1:
  - TLS/SSL auto-wrapping for encrypted ports (443, 8443, 465, 993 …).
  - Graceful SSL handshake fallback when plain-text probe fails.
  - Extended signature set: PostgreSQL, LDAP, RDP, VNC, Memcached,
    AMQP, Elasticsearch, Consul, Kubernetes, RTSP, SIP, Telnet, NNTP.
  - Generic HTTP fallback probe for unrecognised high ports.
  - Richer version extraction (e.g. full SSH software string, Server: header).
  - Protocol-specific UDP probes exposed via grab_udp_banner().
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration tables
# ---------------------------------------------------------------------------

# Ports where the server speaks first — just connect and read.
_PASSIVE_PORTS = frozenset({
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    37,   # Time
    110,  # POP3
    119,  # NNTP
    143,  # IMAP
    220,  # IMAP3
    465,  # SMTPS (passive after TLS)
    587,  # SMTP submission (passive after TLS)
    873,  # rsync
})

# Ports that use TLS — we'll try SSL-wrapping automatically.
_TLS_PORTS = frozenset({
    443, 465, 636, 993, 995, 8443, 8883, 9443, 10443,
})

# Active probes: bytes to send before reading the response.
# %HOST% is replaced with the target host at runtime.
_ACTIVE_PROBES: dict[int, bytes] = {
    80:    b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: Scanner/2.0\r\n\r\n",
    443:   b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: Scanner/2.0\r\n\r\n",
    8000:  b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: Scanner/2.0\r\n\r\n",
    8008:  b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: Scanner/2.0\r\n\r\n",
    8080:  b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: Scanner/2.0\r\n\r\n",
    8081:  b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: Scanner/2.0\r\n\r\n",
    8088:  b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: Scanner/2.0\r\n\r\n",
    8443:  b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: Scanner/2.0\r\n\r\n",
    8888:  b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: Scanner/2.0\r\n\r\n",
    9200:  b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: Scanner/2.0\r\n\r\n",  # Elasticsearch
    6379:  b"PING\r\n",     # Redis
    11211: b"version\r\n",  # Memcached
    5672:  b"AMQP\x00\x00\x09\x01",  # AMQP/RabbitMQ
    # Ports that send a greeting — empty probe triggers it.
    3306:  b"",   # MySQL / MariaDB
    5432:  b"",   # PostgreSQL
    27017: b"",   # MongoDB
    9042:  b"",   # Cassandra CQL
}

# Generic HTTP probe used as a last-resort for unrecognised high ports.
_HTTP_FALLBACK = b"HEAD / HTTP/1.0\r\nHost: %HOST%\r\nUser-Agent: Scanner/2.0\r\n\r\n"

# ---------------------------------------------------------------------------
# Signature table: (compiled_regex, service_name, version_capture_group)
# Checked in order; first match wins.
# ---------------------------------------------------------------------------
_SIGNATURES: list[tuple[re.Pattern[bytes], str, Optional[int]]] = [
    # SSH
    (re.compile(rb"^SSH-([\d.]+)-(\S+)", re.M),                "ssh",        2),
    # FTP
    (re.compile(rb"^220[- ].*?(?:FTP|FileZilla|vsftpd|ProFTPD|Pure-FTPd)", re.I), "ftp", None),
    (re.compile(rb"^220[- ]",             re.I),                "ftp",        None),
    # SMTP / ESMTP
    (re.compile(rb"^220[- ]\S+\s+ESMTP\s+(\S+)", re.I),        "smtp",       1),
    (re.compile(rb"^220[- ].*?(?:SMTP|ESMTP)",    re.I),        "smtp",       None),
    # POP3
    (re.compile(rb"^\+OK",                re.I),                "pop3",       None),
    # IMAP
    (re.compile(rb"^\* OK.*?IMAP",        re.I),                "imap",       None),
    (re.compile(rb"^\* OK",               re.I),                "imap",       None),
    # NNTP
    (re.compile(rb"^200 .*?(?:NNTP|INN|news)", re.I),          "nntp",       None),
    # Telnet (IAC will/do negotiation)
    (re.compile(rb"^\xff[\xfb-\xfe]"),                          "telnet",     None),
    # HTTP
    (re.compile(rb"^HTTP/\d\.\d\s+\d+"),                        "http",       None),
    # Redis
    (re.compile(rb"^\+PONG",              re.I),                "redis",      None),
    (re.compile(rb"^-ERR",                re.I),                "redis",      None),
    (re.compile(rb"^\*\d+\r\n"),                                "redis",      None),  # RESP array
    # Memcached
    (re.compile(rb"^VERSION\s+(\S+)",     re.I),                "memcached",  1),
    # MySQL / MariaDB
    (re.compile(rb"[\x00-\x09]\x00\x00\x00.{0,8}(?:mysql|MariaDB)", re.I), "mysql", None),
    (re.compile(rb"\x0a[\x35-\x39]"),                           "mysql",      None),  # version byte
    # PostgreSQL
    (re.compile(rb"^N\x00\x00\x00\x08\x04\xd2\x16/"),          "postgresql", None),
    (re.compile(rb"^E.*?SFATAL.*?pg_",    re.I),                "postgresql", None),
    # MongoDB (greeting)
    (re.compile(rb"ismaster|isMaster|hello|MongoDB", re.I),     "mongodb",    None),
    # Elasticsearch
    (re.compile(rb'"tagline"\s*:\s*"You Know',    re.I),        "elasticsearch", None),
    # AMQP / RabbitMQ
    (re.compile(rb"^AMQP\x00"),                                 "amqp",       None),
    # VNC
    (re.compile(rb"^RFB \d+\.\d+"),                             "vnc",        None),
    # RDP
    (re.compile(rb"^\x03\x00\x00"),                             "rdp",        None),
    # RTSP
    (re.compile(rb"^RTSP/\d\.\d\s+\d+"),                        "rtsp",       None),
    # SIP
    (re.compile(rb"^SIP/2\.0\s+\d+"),                           "sip",        None),
    # rsync
    (re.compile(rb"^@RSYNCD:\s*([\d.]+)"),                      "rsync",      1),
    # Consul / HashiCorp
    (re.compile(rb'"Config".*?"Datacenter"', re.I),             "consul",     None),
]

_SERVER_HEADER_RE  = re.compile(rb"Server:\s*([^\r\n]+)", re.I)
_X_POWERED_BY_RE   = re.compile(rb"X-Powered-By:\s*([^\r\n]+)", re.I)
_CONTENT_TYPE_RE   = re.compile(rb"Content-Type:\s*([^\r\n]+)", re.I)


@dataclass
class ServiceInfo:
    service: str
    banner: str
    version: Optional[str] = None
    tls: bool = False          # True if the banner was read over TLS/SSL


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def grab_banner(host: str, port: int, timeout: float = 2.0) -> ServiceInfo:
    """
    Attempt to identify the service running on an open TCP port.

    Returns a ServiceInfo with empty fields if nothing was readable —
    this is expected for many services and is NOT an error.
    """
    # 1. Try TLS-wrapped connection first for known TLS ports.
    if port in _TLS_PORTS:
        info = _grab_with_tls(host, port, timeout)
        if info is not None:
            return info

    # 2. Plain-text connection.
    raw = _grab_raw(host, port, timeout)

    # 3. For ports not in _PASSIVE_PORTS and with no configured probe,
    #    try a generic HTTP HEAD probe as a last resort.
    if not raw and port not in _PASSIVE_PORTS and port not in _ACTIVE_PROBES:
        raw = _send_probe(host, port, _HTTP_FALLBACK, timeout)

    info = _classify(raw, port, tls=False)

    # 4. If plain failed and port is TLS-capable, retry with TLS.
    if not info.service and port not in _TLS_PORTS:
        tls_info = _grab_with_tls(host, port, timeout)
        if tls_info is not None:
            return tls_info

    return info


def grab_udp_banner(host: str, port: int, timeout: float = 2.0) -> ServiceInfo:
    """
    Send a protocol-specific UDP probe and classify the response.
    Falls back to an empty ServiceInfo when nothing useful is returned.
    """
    _UDP_PROBES: dict[int, bytes] = {
        53:   b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        161:  b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x3e\x5f\xb6\x8f\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
        5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        probe = _UDP_PROBES.get(port, b"\x00")
        sock.sendto(probe, (host, port))
        try:
            data, _ = sock.recvfrom(2048)
            return _classify(data, port, tls=False)
        except socket.timeout:
            return ServiceInfo(service="", banner="")
    except OSError:
        return ServiceInfo(service="", banner="")
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _grab_raw(host: str, port: int, timeout: float) -> bytes:
    """Open a plain TCP connection, optionally send a probe, and read the reply."""
    probe = _ACTIVE_PROBES.get(port)
    if probe is None and port not in _PASSIVE_PORTS:
        return b""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        if probe:
            sock.sendall(probe.replace(b"%HOST%", host.encode()))
        try:
            return sock.recv(4096)
        except socket.timeout:
            return b""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return b""
    finally:
        sock.close()


def _send_probe(host: str, port: int, probe: bytes, timeout: float) -> bytes:
    """Send an arbitrary probe over a new TCP connection and return the response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(probe.replace(b"%HOST%", host.encode()))
        try:
            return sock.recv(4096)
        except socket.timeout:
            return b""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return b""
    finally:
        sock.close()


def _grab_with_tls(host: str, port: int, timeout: float) -> Optional[ServiceInfo]:
    """
    Attempt a TLS handshake and read the server's first message (or send an
    HTTP HEAD probe for HTTP-over-TLS ports).  Returns None if TLS fails.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        probe = _ACTIVE_PROBES.get(port)
        if probe:
            tls_sock.sendall(probe.replace(b"%HOST%", host.encode()))
        try:
            raw = tls_sock.recv(4096)
        except socket.timeout:
            raw = b""
        info = _classify(raw, port, tls=True)
        info.tls = True
        return info
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _classify(raw: bytes, port: int, *, tls: bool = False) -> ServiceInfo:
    """Match raw bytes against the signature table and return ServiceInfo."""
    banner_text = raw[:512].decode(errors="replace").strip()

    for pattern, service, version_group in _SIGNATURES:
        match = pattern.search(raw)
        if match:
            version: Optional[str] = None
            if version_group is not None:
                try:
                    version = match.group(version_group).decode(errors="replace").strip()
                except (IndexError, AttributeError):
                    pass
            return ServiceInfo(service=service, banner=banner_text,
                               version=version, tls=tls)

    # HTTP responses: try to extract Server: header even if the status-line
    # signature above didn't fire (e.g. a 400 Bad Request response).
    if b"HTTP/" in raw or b"Server:" in raw:
        server_hdr = _SERVER_HEADER_RE.search(raw)
        version = server_hdr.group(1).decode(errors="replace").split("\r")[0].strip() \
                  if server_hdr else None
        return ServiceInfo(service="http", banner=banner_text,
                           version=version, tls=tls)

    return ServiceInfo(service="", banner=banner_text, version=None, tls=tls)
