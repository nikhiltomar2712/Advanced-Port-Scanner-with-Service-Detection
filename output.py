"""
output.py
----------
Two responsibilities:
  1. Pretty, color-coded console rendering of results as they come in
     and as a final summary table.
  2. Exporting the full result set to JSON, CSV, plain TXT, and a
     simple self-contained HTML report.

Colors are implemented with raw ANSI escape codes (no colorama
dependency) and are automatically disabled when stdout isn't a TTY
(e.g. when piping to a file) or on platforms where they're unsupported.
"""

from __future__ import annotations

import csv
import html
import json
import sys
from datetime import datetime, timezone
from typing import List

from .scanner import ScanResult


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @staticmethod
    def enabled() -> bool:
        return sys.stdout.isatty()


def _c(text: str, color: str) -> str:
    if not Colors.enabled():
        return text
    return f"{color}{text}{Colors.RESET}"


STATE_COLORS = {
    "open": Colors.GREEN,
    "closed": Colors.RED,
    "filtered": Colors.YELLOW,
    "open|filtered": Colors.YELLOW,
    "error": Colors.DIM,
}


def print_banner() -> None:
    banner = r"""
   ___           _      ____                            
  / _ \___  ____| |_   / __/______ _____  ___  ___ ____
 / ___/ _ \/ __/ __/  _\ \/ __/ _ `/ _ \/ _ \/ -_) __/
/_/   \___/_/  \__/  /___/\__/\_,_/_//_/_//_/\__/_/
                                  Advanced Port Scanner
"""
    print(_c(banner, Colors.CYAN))


def print_result_line(result: ScanResult, verbose: bool = False) -> None:
    """Print one line as a result comes in (used during a live scan)."""
    if result.state == "closed" and not verbose:
        return  # keep live output focused on interesting findings
    color = STATE_COLORS.get(result.state, "")
    state_label = _c(f"{result.state:>14}", color)
    line = f"{result.host:<18} {result.port:>6}/{result.protocol:<3} {state_label}  {result.service}"
    if result.banner:
        line += f"  {_c(result.banner[:60], Colors.DIM)}"
    if result.error and verbose:
        line += f"  {_c('(' + result.error + ')', Colors.DIM)}"
    print(line)


def print_summary(results: List[ScanResult], elapsed_seconds: float) -> None:
    open_count = sum(1 for r in results if r.state == "open")
    closed_count = sum(1 for r in results if r.state == "closed")
    filtered_count = sum(1 for r in results if r.state in ("filtered", "open|filtered"))
    error_count = sum(1 for r in results if r.state == "error")

    print()
    print(_c("=" * 60, Colors.CYAN))
    print(_c("SCAN SUMMARY", Colors.BOLD))
    print(_c("=" * 60, Colors.CYAN))
    print(f"  Total ports scanned : {len(results)}")
    print(f"  {_c('Open', Colors.GREEN):<19}: {open_count}")
    print(f"  {_c('Closed', Colors.RED):<19}: {closed_count}")
    print(f"  {_c('Filtered', Colors.YELLOW):<19}: {filtered_count}")
    if error_count:
        print(f"  {_c('Errors', Colors.DIM):<19}: {error_count}")
    print(f"  Elapsed time         : {elapsed_seconds:.2f}s")
    print(_c("=" * 60, Colors.CYAN))

    open_results = [r for r in results if r.state == "open"]
    if open_results:
        print()
        print(_c("OPEN PORTS", Colors.BOLD))
        for r in sorted(open_results, key=lambda x: (x.host, x.port)):
            svc = r.service or "unknown"
            extra = f" - {r.banner[:50]}" if r.banner else ""
            print(f"  {_c(str(r.port), Colors.GREEN):>6}/{r.protocol}  {svc}{extra}")


def _result_to_dict(r: ScanResult) -> dict:
    return {
        "host": r.host,
        "port": r.port,
        "protocol": r.protocol,
        "state": r.state,
        "service": r.service,
        "banner": r.banner,
        "response_time_ms": round(r.response_time_ms, 2) if r.response_time_ms else None,
        "scan_type": r.scan_type,
        "error": r.error,
    }


def export_json(results: List[ScanResult], path: str, metadata: dict | None = None) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": metadata or {},
        "results": [_result_to_dict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def export_csv(results: List[ScanResult], path: str) -> None:
    fieldnames = ["host", "port", "protocol", "state", "service", "banner",
                  "response_time_ms", "scan_type", "error"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(_result_to_dict(r))


def export_txt(results: List[ScanResult], path: str, metadata: dict | None = None) -> None:
    lines = []
    lines.append("Advanced Port Scanner - Results")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    if metadata:
        for k, v in metadata.items():
            lines.append(f"{k}: {v}")
    lines.append("-" * 70)
    lines.append(f"{'HOST':<18}{'PORT':>8}  {'PROTO':<6}{'STATE':<14}{'SERVICE':<12}BANNER")
    lines.append("-" * 70)
    for r in sorted(results, key=lambda x: (x.host, x.port)):
        banner = (r.banner or "")[:40]
        lines.append(
            f"{r.host:<18}{r.port:>8}  {r.protocol:<6}{r.state:<14}{r.service:<12}{banner}"
        )
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Port Scan Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; background: #0f1117; color: #e6e6e6; }}
  h1 {{ color: #4fd1c5; }}
  .meta {{ color: #9aa0a6; margin-bottom: 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; background: #161922; }}
  th, td {{ padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid #2a2e3a; font-size: 0.9rem; }}
  th {{ background: #1f2330; color: #8be9fd; position: sticky; top: 0; }}
  tr:hover {{ background: #1d2130; }}
  .state-open {{ color: #50fa7b; font-weight: 600; }}
  .state-closed {{ color: #ff5555; }}
  .state-filtered, .state-open-filtered {{ color: #f1fa8c; }}
  .state-error {{ color: #6272a4; }}
  .summary {{ display: flex; gap: 1.5rem; margin-bottom: 1.5rem; }}
  .card {{ background: #161922; padding: 1rem 1.5rem; border-radius: 8px; min-width: 120px; }}
  .card .num {{ font-size: 1.8rem; font-weight: 700; }}
  .card .label {{ color: #9aa0a6; font-size: 0.8rem; text-transform: uppercase; }}
  .disclaimer {{ margin-top: 2rem; padding: 1rem; border: 1px solid #ff5555; border-radius: 6px; color: #ff8888; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>Advanced Port Scanner - Report</h1>
<div class="meta">Generated {generated_at}{metadata_line}</div>
<div class="summary">
  <div class="card"><div class="num">{total}</div><div class="label">Total scanned</div></div>
  <div class="card"><div class="num" style="color:#50fa7b">{open_count}</div><div class="label">Open</div></div>
  <div class="card"><div class="num" style="color:#ff5555">{closed_count}</div><div class="label">Closed</div></div>
  <div class="card"><div class="num" style="color:#f1fa8c">{filtered_count}</div><div class="label">Filtered</div></div>
</div>
<table>
<thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Banner</th><th>RTT (ms)</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
<div class="disclaimer">
  This report was generated by Advanced Port Scanner for authorized testing only.
  Scanning systems without explicit permission may be illegal in your jurisdiction.
</div>
</body>
</html>
"""


def export_html(results: List[ScanResult], path: str, metadata: dict | None = None) -> None:
    open_count = sum(1 for r in results if r.state == "open")
    closed_count = sum(1 for r in results if r.state == "closed")
    filtered_count = sum(1 for r in results if r.state in ("filtered", "open|filtered"))

    rows = []
    for r in sorted(results, key=lambda x: (x.host, x.port)):
        if r.state == "open|filtered":
            css_class = "state-open-filtered"
        else:
            css_class = f"state-{r.state}"
        rows.append(
            "<tr>"
            f"<td>{html.escape(r.host)}</td>"
            f"<td>{r.port}</td>"
            f"<td>{html.escape(r.protocol)}</td>"
            f"<td class=\"{css_class}\">{html.escape(r.state)}</td>"
            f"<td>{html.escape(r.service or '')}</td>"
            f"<td>{html.escape((r.banner or '')[:80])}</td>"
            f"<td>{round(r.response_time_ms, 1) if r.response_time_ms else ''}</td>"
            "</tr>"
        )

    metadata_line = ""
    if metadata:
        metadata_line = " &mdash; " + ", ".join(f"{k}: {html.escape(str(v))}" for k, v in metadata.items())

    page = _HTML_TEMPLATE.format(
        generated_at=datetime.now(timezone.utc).isoformat(),
        metadata_line=metadata_line,
        total=len(results),
        open_count=open_count,
        closed_count=closed_count,
        filtered_count=filtered_count,
        rows="\n".join(rows) if rows else "<tr><td colspan=7>No results</td></tr>",
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
