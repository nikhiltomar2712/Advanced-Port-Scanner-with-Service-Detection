"""
cli.py
-------
Argument parsing and top-level orchestration. Kept deliberately "thin":
all the real logic lives in scanner.py / service_detection.py /
os_fingerprint.py / output.py / network_utils.py -- this module just
wires user input to those pieces and drives the scan loop.
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from . import network_utils, output, profiles
from .os_fingerprint import fingerprint as os_fingerprint
from .ports_data import TOP_100_PORTS
from .progress import ProgressBar
from .scanner import ScanEngine, ScanResult, SCAPY_AVAILABLE
from .service_detection import grab_banner

LARGE_SCAN_WARNING_THRESHOLD = 200_000

DISCLAIMER = """\
================================================================
  LEGAL / ETHICAL NOTICE
  Only scan systems you OWN or are explicitly AUTHORIZED to test.
  Unauthorized port scanning may violate computer-misuse laws in
  your jurisdiction (and the target's). You are solely responsible
  for how you use this tool.
================================================================
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port_scanner.py",
        description="Advanced TCP/UDP port scanner with service detection and basic OS fingerprinting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python port_scanner.py -t 192.168.1.1 -p 1-1000 -sT -v --threads 100
  python port_scanner.py -t example.com --top-ports 100 --service-detection
  python port_scanner.py -t 10.0.0.0/28 --ping-sweep --top-ports 100
  python port_scanner.py -t 192.168.1.1 -p 1-65535 -sS --os-detection -oJ results.json
""",
    )

    parser.add_argument("-t", "--target", required=True,
                         help="Target host/IP, hostname, CIDR range, or comma-separated list.")

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument("-p", "--ports", default=None,
                             help="Port(s): single (80), range (1-1024), list (22,80,443), or 'all'.")
    port_group.add_argument("--top-ports", type=int, default=None, metavar="N",
                             help="Scan the N most common ports instead of specifying -p (e.g. 100, 1000).")

    scan_type = parser.add_mutually_exclusive_group()
    scan_type.add_argument("-sT", dest="scan_type", action="store_const", const="tcp",
                            help="TCP connect scan (default, no special privileges needed).")
    scan_type.add_argument("-sU", dest="scan_type", action="store_const", const="udp",
                            help="UDP scan.")
    scan_type.add_argument("-sS", dest="scan_type", action="store_const", const="syn",
                            help="TCP SYN / half-open scan (requires scapy + root/admin; "
                                 "falls back to -sT automatically otherwise).")
    parser.set_defaults(scan_type="tcp")

    parser.add_argument("--threads", type=int, default=50,
                         help="Number of concurrent worker threads (default: 50).")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Per-port socket timeout in seconds (default: 1.0).")
    parser.add_argument("--delay", type=float, default=0.0,
                         help="Delay in seconds before each individual probe, for "
                              "rate-limited/respectful scanning (default: 0, no delay).")

    parser.add_argument("--service-detection", action="store_true",
                         help="Attempt banner grabbing / service & version identification on open ports.")
    parser.add_argument("--os-detection", action="store_true",
                         help="Attempt basic OS fingerprinting (TTL-based, plus TCP window size if scapy is available).")
    parser.add_argument("--ping-sweep", action="store_true",
                         help="Ping hosts first and skip ones that don't respond (host discovery).")

    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show closed/filtered ports too, plus extra diagnostic detail.")
    parser.add_argument("-y", "--yes", action="store_true",
                         help="Skip the interactive authorization confirmation prompt.")
    parser.add_argument("--log-file", default=None, help="Write a detailed log to this file.")

    parser.add_argument("-oJ", "--output-json", metavar="FILE", help="Export results as JSON.")
    parser.add_argument("-oC", "--output-csv", metavar="FILE", help="Export results as CSV.")
    parser.add_argument("-oT", "--output-txt", metavar="FILE", help="Export results as plain text.")
    parser.add_argument("-oH", "--output-html", metavar="FILE", help="Export results as an HTML report.")

    parser.add_argument("--save-profile", metavar="NAME", help="Save these options as a reusable named profile.")
    parser.add_argument("--load-profile", metavar="NAME", help="Load options from a previously saved profile.")
    parser.add_argument("--list-profiles", action="store_true", help="List saved profiles and exit.")

    return parser


def _apply_profile_defaults(args: argparse.Namespace, raw_argv: List[str]) -> None:
    """Fill in any option not explicitly passed on the command line from a saved profile."""
    try:
        saved = profiles.load_profile(args.load_profile)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    explicit_flags = {
        "target": ("-t", "--target"), "ports": ("-p", "--ports"),
        "top_ports": ("--top-ports",), "scan_type": ("-sT", "-sU", "-sS"),
        "threads": ("--threads",), "timeout": ("--timeout",), "delay": ("--delay",),
        "service_detection": ("--service-detection",), "os_detection": ("--os-detection",),
        "ping_sweep": ("--ping-sweep",), "verbose": ("-v", "--verbose"),
        "output_json": ("-oJ", "--output-json"), "output_csv": ("-oC", "--output-csv"),
        "output_txt": ("-oT", "--output-txt"), "output_html": ("-oH", "--output-html"),
    }
    for key, value in saved.items():
        flags = explicit_flags.get(key, ())
        if any(flag in raw_argv for flag in flags):
            continue  # user explicitly overrode this on the command line
        setattr(args, key, value)


def _confirm_authorization(args: argparse.Namespace) -> bool:
    if args.yes:
        return True
    print(DISCLAIMER)
    try:
        answer = input("Type 'yes' to confirm you are authorized to scan this target: ").strip().lower()
    except EOFError:
        return False
    return answer == "yes"


def _setup_logging(log_file: str | None, verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stderr)] if False else []  # keep console clean; file only
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(level=level, handlers=handlers or [logging.NullHandler()],
                         format="%(asctime)s [%(levelname)s] %(message)s")


def run_scan(host: str, port: int, scan_type: str, engine: ScanEngine) -> ScanResult:
    if scan_type == "udp":
        return engine.udp_scan(host, port)
    if scan_type == "syn":
        return engine.syn_scan(host, port)
    return engine.tcp_connect_scan(host, port)


def main(argv: List[str] | None = None) -> int:
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(raw_argv)

    if args.list_profiles:
        names = profiles.list_profiles()
        if names:
            print("Saved profiles:\n  " + "\n  ".join(names))
        else:
            print("No saved profiles yet. Use --save-profile NAME to create one.")
        return 0

    if args.load_profile:
        _apply_profile_defaults(args, raw_argv)

    _setup_logging(args.log_file, args.verbose)
    log = logging.getLogger("port_scanner")

    output.print_banner()

    if not _confirm_authorization(args):
        print("Authorization not confirmed. Aborting.")
        return 1

    # --- Resolve targets ---
    try:
        targets = network_utils.parse_targets(args.target)
    except network_utils.TargetParseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.ping_sweep:
        print(f"Ping sweeping {len(targets)} host(s)...")
        alive = network_utils.ping_sweep(targets, timeout=min(args.timeout, 1.0))
        print(f"  {len(alive)}/{len(targets)} host(s) responded to ping.")
        if not alive:
            print("No hosts are up (or all silently drop ICMP). Continuing with the full target list anyway.")
        else:
            targets = alive

    # --- Resolve ports ---
    try:
        if args.top_ports is not None:
            ports = network_utils.top_ports(args.top_ports)
        elif args.ports is not None:
            ports = network_utils.parse_ports(args.ports)
        else:
            ports = list(TOP_100_PORTS)  # sensible default: quick triage scan
    except network_utils.PortParseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.scan_type == "syn" and not SCAPY_AVAILABLE:
        print("Note: scapy is not installed -- SYN scan (-sS) will fall back to a TCP connect scan.")
        print("      Install with: pip install scapy   (and run as root/Administrator for true SYN scans)\n")

    total_tasks = len(targets) * len(ports)
    if total_tasks > LARGE_SCAN_WARNING_THRESHOLD and not args.yes:
        print(f"This scan covers {total_tasks:,} host/port combinations and may take a long time.")
        try:
            proceed = input("Continue anyway? [y/N]: ").strip().lower()
        except EOFError:
            proceed = "n"
        if proceed != "y":
            print("Aborted.")
            return 1

    print(f"\nTargets: {len(targets)}   Ports: {len(ports)}   Scan type: {args.scan_type.upper()}   "
          f"Threads: {args.threads}\n")

    engine = ScanEngine(timeout=args.timeout, delay=args.delay)
    results: List[ScanResult] = []
    progress = ProgressBar(total_tasks, label="Scanning")

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=max(args.threads, 1)) as pool:
        futures = {}
        for host in targets:
            for port in ports:
                futures[pool.submit(run_scan, host, port, args.scan_type, engine)] = (host, port)

        for future in as_completed(futures):
            host, port = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                result = ScanResult(host, port, args.scan_type, "error", error=str(exc))
            results.append(result)
            log.debug("%s:%s -> %s", host, port, result.state)
            progress.update()
            if not progress.enabled:
                output.print_result_line(result, verbose=args.verbose)
    progress.finish()
    elapsed = time.time() - start_time

    # --- Service detection on open TCP ports ---
    if args.service_detection:
        open_tcp = [r for r in results if r.state == "open" and r.protocol == "tcp"]
        if open_tcp:
            print(f"Running service detection on {len(open_tcp)} open port(s)...")
            with ThreadPoolExecutor(max_workers=min(args.threads, max(len(open_tcp), 1))) as pool:
                future_map = {pool.submit(grab_banner, r.host, r.port, max(args.timeout, 2.0)): r
                              for r in open_tcp}
                for future in as_completed(future_map):
                    r = future_map[future]
                    try:
                        info = future.result()
                        if info.service:
                            r.service = info.service
                        if info.banner:
                            r.banner = info.banner
                        if info.version:
                            r.banner = f"{r.banner} [{info.version}]".strip()
                    except Exception as exc:  # pragma: no cover
                        log.debug("service detection failed for %s:%s -> %s", r.host, r.port, exc)

    # --- OS fingerprinting (once per host) ---
    os_guesses = {}
    if args.os_detection:
        print("Running OS fingerprinting...")
        hosts_with_open_tcp = {}
        for r in results:
            if r.state == "open" and r.protocol == "tcp" and r.host not in hosts_with_open_tcp:
                hosts_with_open_tcp[r.host] = r.port
        for host in targets:
            fp = os_fingerprint(host, hosts_with_open_tcp.get(host), timeout=max(args.timeout, 1.5))
            os_guesses[host] = fp
            print(f"  {host}: {fp.guess} (confidence: {fp.confidence})"
                  + (f" -- TTL={fp.observed_ttl}" if fp.observed_ttl else ""))

    # --- Summary + export ---
    output.print_summary(results, elapsed)

    metadata = {
        "target_spec": args.target,
        "scan_type": args.scan_type,
        "ports_scanned": len(ports),
        "hosts_scanned": len(targets),
        "elapsed_seconds": round(elapsed, 2),
    }
    if os_guesses:
        metadata["os_fingerprints"] = {h: fp.guess for h, fp in os_guesses.items()}

    if args.output_json:
        output.export_json(results, args.output_json, metadata)
        print(f"\nJSON report written to {args.output_json}")
    if args.output_csv:
        output.export_csv(results, args.output_csv)
        print(f"CSV report written to {args.output_csv}")
    if args.output_txt:
        output.export_txt(results, args.output_txt, metadata)
        print(f"TXT report written to {args.output_txt}")
    if args.output_html:
        output.export_html(results, args.output_html, metadata)
        print(f"HTML report written to {args.output_html}")

    if args.save_profile:
        path = profiles.save_profile(args.save_profile, args)
        print(f"Profile saved to {path}")

    return 0
