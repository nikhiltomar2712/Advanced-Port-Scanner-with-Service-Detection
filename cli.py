"""
cli.py
-------
Argument parsing and top-level orchestration.

Upgrades over v1:
  - Graceful Ctrl-C (SIGINT) handling — prints partial results and exits cleanly.
  - --exclude-ports  : skip specific ports even within a range.
  - --exclude-hosts  : skip specific hosts within a CIDR / range.
  - --retries        : per-port retry count for noisy/unreliable links.
  - --output-xml     : Nmap-compatible XML export.
  - --format         : alias for output format selection (alternative to -oX flags).
  - SSH banner is forwarded to os_fingerprint for better OS hints.
  - Live output header line before scan starts.
  - TLS flag surfaced in ScanResult after service detection.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

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
  Only scan systems you OWN or are EXPLICITLY AUTHORIZED to test.
  Unauthorized port scanning may violate laws in your jurisdiction.
  You are solely responsible for how you use this tool.
================================================================
"""

# Global flag — set by the SIGINT handler to trigger graceful shutdown.
_shutdown_requested = False


def _sigint_handler(sig: int, frame) -> None:  # noqa: ANN001
    global _shutdown_requested
    print("\n\n[!] Scan interrupted by user — collecting partial results…",
          file=sys.stderr)
    _shutdown_requested = True


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port_scanner",
        description=(
            "Advanced TCP/UDP port scanner with service detection, "
            "TLS identification, and basic OS fingerprinting."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python -m port_scanner -t 192.168.1.1 -p 1-1000 -sT -v --threads 100
  python -m port_scanner -t example.com --top-ports 100 --service-detection
  python -m port_scanner -t 10.0.0.0/28 --ping-sweep --top-ports 100
  python -m port_scanner -t 192.168.1.1 -p 1-65535 -sS --os-detection -oX results.xml
  python -m port_scanner -t 10.0.0.0/24 --top-ports 1000 --exclude-ports 443,8443
""",
    )

    # -- Target & ports --
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target host/IP, hostname, CIDR range, IP range (10.0.0.1-50), "
             "or comma-separated list.",
    )

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p", "--ports", default=None,
        help="Port(s): single (80), range (1-1024), list (22,80,443), or 'all'.",
    )
    port_group.add_argument(
        "--top-ports", type=int, default=None, metavar="N",
        help="Scan the N most common ports (e.g. 100, 1000).",
    )

    parser.add_argument(
        "--exclude-ports", default=None, metavar="PORTS",
        help="Comma-separated ports to exclude from the scan (e.g. 443,8443).",
    )
    parser.add_argument(
        "--exclude-hosts", default=None, metavar="HOSTS",
        help="Comma-separated hosts/CIDRs to exclude from the scan.",
    )

    # -- Scan type --
    scan_type = parser.add_mutually_exclusive_group()
    scan_type.add_argument(
        "-sT", dest="scan_type", action="store_const", const="tcp",
        help="TCP connect scan (default, no special privileges needed).",
    )
    scan_type.add_argument(
        "-sU", dest="scan_type", action="store_const", const="udp",
        help="UDP scan.",
    )
    scan_type.add_argument(
        "-sS", dest="scan_type", action="store_const", const="syn",
        help="TCP SYN / half-open scan (requires scapy + root/admin).",
    )
    parser.set_defaults(scan_type="tcp")

    # -- Performance --
    parser.add_argument("--threads", type=int, default=50,
                        help="Concurrent worker threads (default: 50).")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Per-port socket timeout in seconds (default: 1.0).")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Delay in seconds before each probe (rate limiting).")
    parser.add_argument("--retries", type=int, default=0,
                        help="Retry count per port on timeout (default: 0).")

    # -- Detection --
    parser.add_argument("--service-detection", action="store_true",
                        help="Banner grabbing / service & version identification.")
    parser.add_argument("--os-detection", action="store_true",
                        help="Basic OS fingerprinting (TTL + TCP window size).")
    parser.add_argument("--ping-sweep", action="store_true",
                        help="Ping hosts before scanning; skip non-responsive ones.")

    # -- Output --
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show closed/filtered ports and extra detail.")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip the authorization confirmation prompt.")
    parser.add_argument("--log-file", default=None,
                        help="Write a detailed log to this file.")
    parser.add_argument("-oJ", "--output-json", metavar="FILE",
                        help="Export results as JSON.")
    parser.add_argument("-oC", "--output-csv",  metavar="FILE",
                        help="Export results as CSV.")
    parser.add_argument("-oT", "--output-txt",  metavar="FILE",
                        help="Export results as plain text.")
    parser.add_argument("-oH", "--output-html", metavar="FILE",
                        help="Export results as an HTML report (recommended).")
    parser.add_argument("-oX", "--output-xml",  metavar="FILE",
                        help="Export results as Nmap-compatible XML.")

    # -- Profiles --
    parser.add_argument("--save-profile",  metavar="NAME",
                        help="Save current options as a reusable named profile.")
    parser.add_argument("--load-profile",  metavar="NAME",
                        help="Load options from a previously saved profile.")
    parser.add_argument("--list-profiles", action="store_true",
                        help="List saved profiles and exit.")

    return parser


# ---------------------------------------------------------------------------
# Profile helpers
# ---------------------------------------------------------------------------

def _apply_profile_defaults(args: argparse.Namespace, raw_argv: List[str]) -> None:
    try:
        saved = profiles.load_profile(args.load_profile)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    explicit_flags = {
        "target":            ("-t", "--target"),
        "ports":             ("-p", "--ports"),
        "top_ports":         ("--top-ports",),
        "exclude_ports":     ("--exclude-ports",),
        "exclude_hosts":     ("--exclude-hosts",),
        "scan_type":         ("-sT", "-sU", "-sS"),
        "threads":           ("--threads",),
        "timeout":           ("--timeout",),
        "delay":             ("--delay",),
        "retries":           ("--retries",),
        "service_detection": ("--service-detection",),
        "os_detection":      ("--os-detection",),
        "ping_sweep":        ("--ping-sweep",),
        "verbose":           ("-v", "--verbose"),
        "output_json":       ("-oJ", "--output-json"),
        "output_csv":        ("-oC", "--output-csv"),
        "output_txt":        ("-oT", "--output-txt"),
        "output_html":       ("-oH", "--output-html"),
        "output_xml":        ("-oX", "--output-xml"),
    }
    for key, value in saved.items():
        flags = explicit_flags.get(key, ())
        if any(f in raw_argv for f in flags):
            continue
        setattr(args, key, value)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _confirm_authorization(args: argparse.Namespace) -> bool:
    if args.yes:
        return True
    print(DISCLAIMER)
    try:
        answer = input(
            "Type 'yes' to confirm you are authorized to scan this target: "
        ).strip().lower()
    except EOFError:
        return False
    return answer == "yes"


def _setup_logging(log_file: Optional[str], verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: List[logging.Handler] = []
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        handlers=handlers or [logging.NullHandler()],
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def _run_single(host: str, port: int, scan_type: str, engine: ScanEngine) -> ScanResult:
    if scan_type == "udp":
        return engine.udp_scan(host, port)
    if scan_type == "syn":
        return engine.syn_scan(host, port)
    return engine.tcp_connect_scan(host, port)


def _parse_exclude_ports(raw: Optional[str]) -> set[int]:
    if not raw:
        return set()
    result = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            result.add(int(part))
        except ValueError:
            print(f"Warning: invalid exclude port '{part}' (ignored)", file=sys.stderr)
    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    global _shutdown_requested

    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(raw_argv)

    # -- Profile management ------------------------------------------------
    if args.list_profiles:
        names = profiles.list_profiles()
        if names:
            print("Saved profiles:\n  " + "\n  ".join(names))
        else:
            print("No saved profiles. Use --save-profile NAME to create one.")
        return 0

    if args.load_profile:
        _apply_profile_defaults(args, raw_argv)

    _setup_logging(args.log_file, args.verbose)
    log = logging.getLogger("port_scanner")

    # -- Banner & authorization --------------------------------------------
    output.print_banner()
    if not _confirm_authorization(args):
        print("Authorization not confirmed. Aborting.")
        return 1

    # -- Register SIGINT handler for graceful Ctrl-C ----------------------
    signal.signal(signal.SIGINT, _sigint_handler)

    # -- Resolve targets ---------------------------------------------------
    try:
        targets = network_utils.parse_targets(args.target)
    except network_utils.TargetParseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # Exclude hosts
    if args.exclude_hosts:
        try:
            excluded_hosts = set()
            for spec in args.exclude_hosts.split(","):
                excluded_hosts.update(network_utils.parse_targets(spec.strip()))
            original_count = len(targets)
            targets = [h for h in targets if h not in excluded_hosts]
            if len(targets) < original_count:
                print(f"Excluded {original_count - len(targets)} host(s).")
        except Exception as exc:
            print(f"Warning: could not parse --exclude-hosts: {exc}", file=sys.stderr)

    if args.ping_sweep:
        print(f"Ping sweeping {len(targets)} host(s)…")
        alive = network_utils.ping_sweep(targets, timeout=min(args.timeout, 1.0))
        print(f"  {len(alive)}/{len(targets)} host(s) responded to ping.")
        if not alive:
            print("No hosts responded to ping; continuing with full target list.")
        else:
            targets = alive

    # -- Resolve ports -----------------------------------------------------
    try:
        if args.top_ports is not None:
            ports = network_utils.top_ports(args.top_ports)
        elif args.ports is not None:
            ports = network_utils.parse_ports(args.ports)
        else:
            ports = list(TOP_100_PORTS)
    except network_utils.PortParseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # Apply port exclusions
    exclude_ports = _parse_exclude_ports(getattr(args, "exclude_ports", None))
    if exclude_ports:
        before = len(ports)
        ports = [p for p in ports if p not in exclude_ports]
        print(f"Excluded {before - len(ports)} port(s) from scan.")

    # -- Pre-flight checks -------------------------------------------------
    if args.scan_type == "syn" and not SCAPY_AVAILABLE:
        print(
            "Note: scapy not installed — SYN scan (-sS) falls back to TCP connect.\n"
            "      Install with: pip install scapy  (run as root for true SYN scans)\n"
        )

    total_tasks = len(targets) * len(ports)
    if total_tasks > LARGE_SCAN_WARNING_THRESHOLD and not args.yes:
        print(f"This scan covers {total_tasks:,} host/port combinations.")
        try:
            proceed = input("Continue anyway? [y/N]: ").strip().lower()
        except EOFError:
            proceed = "n"
        if proceed != "y":
            print("Aborted.")
            return 1

    # -- Scan header -------------------------------------------------------
    scan_start_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(
        f"\nStarted : {scan_start_str}"
        f"\nTargets : {len(targets):,}"
        f"   Ports : {len(ports):,}"
        f"   Type  : {args.scan_type.upper()}"
        f"   Threads: {args.threads}\n"
    )

    # -- Main scan loop ----------------------------------------------------
    engine = ScanEngine(
        timeout=args.timeout,
        delay=args.delay,
        retries=getattr(args, "retries", 0),
    )
    results: List[ScanResult] = []
    progress = ProgressBar(total_tasks, label="Scanning")
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max(args.threads, 1)) as pool:
        futures = {
            pool.submit(_run_single, host, port, args.scan_type, engine): (host, port)
            for host in targets
            for port in ports
        }

        for future in as_completed(futures):
            if _shutdown_requested:
                pool.shutdown(wait=False, cancel_futures=True)
                break

            host, port = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover
                result = ScanResult(host, port, args.scan_type, "error", error=str(exc))

            results.append(result)
            log.debug("%s:%s → %s", host, port, result.state)
            progress.update()

            if not progress.enabled:
                output.print_result_line(result, verbose=args.verbose)

    progress.finish()
    elapsed = time.time() - start_time

    if _shutdown_requested:
        print(
            f"\n[!] Partial scan: {len(results):,} of {total_tasks:,} tasks completed.\n",
            file=sys.stderr,
        )

    # -- Service detection -------------------------------------------------
    if args.service_detection:
        open_tcp = [r for r in results if r.state == "open" and r.protocol == "tcp"]
        if open_tcp:
            print(f"Service detection on {len(open_tcp)} open port(s)…")
            with ThreadPoolExecutor(
                max_workers=min(args.threads, max(len(open_tcp), 1))
            ) as pool:
                future_map = {
                    pool.submit(grab_banner, r.host, r.port, max(args.timeout, 2.0)): r
                    for r in open_tcp
                }
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
                        if getattr(info, "tls", False):
                            r.tls = True  # type: ignore[attr-defined]
                    except Exception as exc:
                        log.debug("service detection failed %s:%s → %s", r.host, r.port, exc)

    # -- OS fingerprinting -------------------------------------------------
    os_guesses: dict[str, object] = {}
    if args.os_detection:
        print("Running OS fingerprinting…")
        hosts_with_open_tcp: dict[str, int] = {}
        for r in results:
            if r.state == "open" and r.protocol == "tcp" and r.host not in hosts_with_open_tcp:
                hosts_with_open_tcp[r.host] = r.port

        # Collect SSH banners per host for better OS hints.
        ssh_banners: dict[str, str] = {}
        for r in results:
            if r.state == "open" and r.service == "ssh" and r.banner:
                ssh_banners.setdefault(r.host, r.banner)

        for host in targets:
            fp = os_fingerprint(
                host,
                open_tcp_port=hosts_with_open_tcp.get(host),
                ssh_banner=ssh_banners.get(host),
                timeout=max(args.timeout, 1.5),
            )
            os_guesses[host] = fp
            ttl_str = f" TTL={fp.observed_ttl}" if fp.observed_ttl else ""
            print(f"  {host}: {fp.guess} [{fp.confidence}]{ttl_str}")

    # -- Summary + export --------------------------------------------------
    output.print_summary(results, elapsed)

    metadata = {
        "target_spec":     args.target,
        "scan_type":       args.scan_type,
        "ports_scanned":   len(ports),
        "hosts_scanned":   len(targets),
        "elapsed_seconds": round(elapsed, 2),
        "started_at":      scan_start_str,
    }
    if os_guesses:
        metadata["os_fingerprints"] = {
            h: fp.guess for h, fp in os_guesses.items()  # type: ignore[union-attr]
        }

    if args.output_json:
        output.export_json(results, args.output_json, metadata)
        print(f"JSON  → {args.output_json}")

    if args.output_csv:
        output.export_csv(results, args.output_csv)
        print(f"CSV   → {args.output_csv}")

    if args.output_txt:
        output.export_txt(results, args.output_txt, metadata)
        print(f"TXT   → {args.output_txt}")

    if args.output_html:
        output.export_html(results, args.output_html, metadata)
        print(f"HTML  → {args.output_html}")

    if args.output_xml:
        output.export_xml(results, args.output_xml, metadata)
        print(f"XML   → {args.output_xml}")

    if args.save_profile:
        path = profiles.save_profile(args.save_profile, args)
        print(f"Profile saved → {path}")

    return 0


# Allow running via `python cli.py` directly as well.
if __name__ == "__main__":
    sys.exit(main())
