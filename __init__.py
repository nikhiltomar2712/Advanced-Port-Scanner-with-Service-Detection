"""
scanner_lib - Core library powering the Advanced Port Scanner.

This package is organized into small, focused modules:
    ports_data        -> static data (top port lists, service name map)
    network_utils      -> target/port parsing, CIDR expansion, ping sweep
    scanner             -> TCP / UDP / SYN scanning engines
    service_detection   -> banner grabbing & service/version guessing
    os_fingerprint       -> lightweight TTL/window based OS guessing
    progress             -> simple dependency-free progress bar
    output                -> console rendering + JSON/CSV/TXT/HTML export
    profiles               -> save/load scan profiles (argparse Namespace <-> JSON)
    cli                      -> argparse wiring + orchestration ("main")
"""

__version__ = "1.0.0"
