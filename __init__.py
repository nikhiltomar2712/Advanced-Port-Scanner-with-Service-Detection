"""
port_scanner — Advanced Port Scanner with Service Detection
===========================================================

A fast, feature-rich Python port scanner with:
  • TCP connect, SYN half-open, and UDP scanning
  • TLS/SSL-aware service & version detection
  • Basic OS fingerprinting (TTL + TCP window + SSH banner)
  • JSON, CSV, TXT, HTML, and Nmap-compatible XML reports
  • Saved scan profiles
  • IPv6 support

Quick start::

    python -m port_scanner -t 192.168.1.1 --top-ports 100 --service-detection

Only scan systems you own or have explicit written permission to scan.
"""

from __future__ import annotations

__version__ = "2.0.0"
__author__  = "nikhiltomar2712"
__license__ = "MIT"

# Expose the public API surface so callers can do:
#   from port_scanner import ScanEngine, ScanResult, grab_banner
from .scanner           import ScanEngine, ScanResult, SCAPY_AVAILABLE  # noqa: F401
from .service_detection import grab_banner, ServiceInfo                  # noqa: F401
from .os_fingerprint    import fingerprint as os_fingerprint             # noqa: F401
from .network_utils     import parse_targets, parse_ports, top_ports     # noqa: F401
from .output            import export_json, export_csv, export_txt, export_html, export_xml  # noqa: F401
