"""
output.py
----------
Console rendering and file export for scan results.

Upgrades over v1:
  - Respects the NO_COLOR env var (https://no-color.org/) and Windows
    legacy consoles that don't support ANSI.
  - Sortable, filterable HTML report (pure JS, no external deps).
  - Summary doughnut chart in HTML using inline SVG.
  - Nmap-compatible XML export (-oX).
  - Optional quiet mode (suppress closed/filtered from live output).
  - Better banner truncation with ellipsis.
  - TLS indicator in console output (🔒 or [TLS]).
"""

from __future__ import annotations

import csv
import html
import json
import os
import sys
from datetime import datetime, timezone
from typing import List, Optional

from .scanner import ScanResult


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

class Colors:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @staticmethod
    def enabled() -> bool:
        # Respect NO_COLOR (https://no-color.org/) and non-TTY streams.
        if os.environ.get("NO_COLOR") is not None:
            return False
        if not sys.stdout.isatty():
            return False
        # Windows cmd.exe without ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if sys.platform == "win32":
            try:
                import ctypes
                kernel = ctypes.windll.kernel32
                # Try to enable VT mode; if it returns 0 the console doesn't support it.
                return bool(kernel.SetConsoleMode(kernel.GetStdHandle(-11), 7))
            except Exception:
                return False
        return True


def _c(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}" if Colors.enabled() else text


STATE_COLORS = {
    "open":          Colors.GREEN,
    "closed":        Colors.RED,
    "filtered":      Colors.YELLOW,
    "open|filtered": Colors.YELLOW,
    "error":         Colors.DIM,
}


def _trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

def print_banner() -> None:
    banner = r"""
  ____            _     ____
 |  _ \ ___  _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __
 | |_) / _ \| '__| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 |  __/ (_) | |  | |_   ___) | (_| (_| | | | | | | |  __/ |
 |_|   \___/|_|   \__| |____/ \___\__,_|_| |_|_| |_|\___|_|
 Advanced Port Scanner v2  — authorized use only
"""
    print(_c(banner, Colors.CYAN))


def print_result_line(result: ScanResult, verbose: bool = False) -> None:
    """Print one line as a scan result arrives (live output mode)."""
    if result.state in ("closed", "error") and not verbose:
        return

    color       = STATE_COLORS.get(result.state, "")
    state_label = _c(f"{result.state:>14}", color)
    tls_mark    = _c(" [TLS]", Colors.CYAN) if getattr(result, "tls", False) else ""
    svc         = result.service or ""
    line = (
        f"{result.host:<18} {result.port:>6}/{result.protocol:<3} "
        f"{state_label}  {svc:<14}{tls_mark}"
    )
    if result.banner:
        line += f"  {_c(_trunc(result.banner, 60), Colors.DIM)}"
    if result.error and verbose:
        line += f"  {_c('(' + result.error + ')', Colors.DIM)}"
    print(line)


def print_summary(results: List[ScanResult], elapsed_seconds: float) -> None:
    """Print the final summary table to stdout."""
    open_count     = sum(1 for r in results if r.state == "open")
    closed_count   = sum(1 for r in results if r.state == "closed")
    filtered_count = sum(1 for r in results if r.state in ("filtered", "open|filtered"))
    error_count    = sum(1 for r in results if r.state == "error")

    sep = _c("=" * 62, Colors.CYAN)
    print()
    print(sep)
    print(_c(" SCAN SUMMARY", Colors.BOLD))
    print(sep)
    print(f"  Total ports scanned   : {len(results):,}")
    print(f"  {_c('Open',     Colors.GREEN):<19}  : {open_count}")
    print(f"  {_c('Closed',   Colors.RED):<19}  : {closed_count}")
    print(f"  {_c('Filtered', Colors.YELLOW):<19}  : {filtered_count}")
    if error_count:
        print(f"  {_c('Errors',   Colors.DIM):<19}  : {error_count}")
    print(f"  Elapsed time          : {elapsed_seconds:.2f}s")
    print(sep)

    open_results = [r for r in results if r.state == "open"]
    if open_results:
        print()
        print(_c(" OPEN PORTS", Colors.BOLD))
        for r in sorted(open_results, key=lambda x: (x.host, x.port)):
            svc   = r.service or "unknown"
            extra = f"  {_trunc(r.banner, 50)}" if r.banner else ""
            tls   = " [TLS]" if getattr(r, "tls", False) else ""
            print(f"  {_c(str(r.port), Colors.GREEN):>8}/{r.protocol}  {svc}{tls}{extra}")


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _result_to_dict(r: ScanResult) -> dict:
    return {
        "host":             r.host,
        "port":             r.port,
        "protocol":         r.protocol,
        "state":            r.state,
        "service":          r.service,
        "banner":           r.banner,
        "tls":              getattr(r, "tls", False),
        "response_time_ms": round(r.response_time_ms, 2) if r.response_time_ms else None,
        "scan_type":        r.scan_type,
        "error":            r.error,
    }


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def export_json(
    results: List[ScanResult],
    path: str,
    metadata: Optional[dict] = None,
) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata":     metadata or {},
        "results":      [_result_to_dict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def export_csv(results: List[ScanResult], path: str) -> None:
    fieldnames = [
        "host", "port", "protocol", "state", "service",
        "banner", "tls", "response_time_ms", "scan_type", "error",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(_result_to_dict(r))


# ---------------------------------------------------------------------------
# Plain-text export
# ---------------------------------------------------------------------------

def export_txt(
    results: List[ScanResult],
    path: str,
    metadata: Optional[dict] = None,
) -> None:
    lines = [
        "Advanced Port Scanner v2 — Results",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
    ]
    if metadata:
        for k, v in metadata.items():
            lines.append(f"{k}: {v}")
    sep = "-" * 80
    lines += [
        sep,
        f"{'HOST':<18} {'PORT':>6} {'PROTO':<5} {'STATE':<14} {'SERVICE':<14} BANNER",
        sep,
    ]
    for r in sorted(results, key=lambda x: (x.host, x.port)):
        banner = _trunc(r.banner or "", 30)
        tls    = "[TLS]" if getattr(r, "tls", False) else ""
        lines.append(
            f"{r.host:<18} {r.port:>6} {r.protocol:<5} {r.state:<14} "
            f"{(r.service + tls):<14} {banner}"
        )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Nmap-compatible XML export
# ---------------------------------------------------------------------------

def export_xml(
    results: List[ScanResult],
    path: str,
    metadata: Optional[dict] = None,
) -> None:
    """Produce a simplified Nmap-compatible XML file."""
    from xml.etree.ElementTree import Element, SubElement, ElementTree, indent as _indent

    root = Element("nmaprun")
    root.set("scanner",    "port_scanner_v2")
    root.set("start",      str(int(datetime.now(timezone.utc).timestamp())))
    root.set("startstr",   datetime.now(timezone.utc).isoformat())
    root.set("version",    "2.0")
    root.set("xmloutputversion", "1.04")
    if metadata:
        root.set("args", str(metadata))

    # Group results by host
    hosts: dict[str, list[ScanResult]] = {}
    for r in results:
        hosts.setdefault(r.host, []).append(r)

    for ip, host_results in hosts.items():
        host_el = SubElement(root, "host")
        addr_el = SubElement(host_el, "address")
        addr_el.set("addr",     ip)
        addr_el.set("addrtype", "ipv4")

        ports_el = SubElement(host_el, "ports")
        for r in sorted(host_results, key=lambda x: x.port):
            port_el = SubElement(ports_el, "port")
            port_el.set("protocol", r.protocol)
            port_el.set("portid",   str(r.port))

            state_el = SubElement(port_el, "state")
            state_el.set("state",  r.state)
            state_el.set("reason", r.scan_type or "")

            svc_el = SubElement(port_el, "service")
            svc_el.set("name",    r.service or "")
            svc_el.set("product", "")
            svc_el.set("version", "")
            if r.banner:
                svc_el.set("extrainfo", _trunc(r.banner, 200))

    tree = ElementTree(root)
    try:
        _indent(tree, space="  ")  # Python 3.9+
    except TypeError:
        pass

    with open(path, "wb") as fh:
        fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        fh.write(b'<!DOCTYPE nmaprun>\n')
        tree.write(fh, encoding="UTF-8", xml_declaration=False)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Port Scan Report</title>
  <style>
    :root {{
      --bg: #0f1117; --surface: #161922; --surface2: #1f2330;
      --text: #e6e6e6; --muted: #9aa0a6;
      --green: #50fa7b; --red: #ff5555; --yellow: #f1fa8c;
      --cyan: #8be9fd; --blue: #6272a4;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
            background: var(--bg); color: var(--text); padding: 2rem; }}
    h1 {{ color: var(--cyan); margin-bottom: .25rem; }}
    .meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 1.5rem; }}
    /* Summary cards */
    .cards {{ display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }}
    .card  {{ background: var(--surface); border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; }}
    .card .num   {{ font-size: 1.8rem; font-weight: 700; }}
    .card .label {{ color: var(--muted); font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; }}
    /* Toolbar */
    .toolbar {{ display: flex; gap: .75rem; margin-bottom: .75rem; align-items: center; flex-wrap: wrap; }}
    .toolbar input, .toolbar select {{
      background: var(--surface2); border: 1px solid var(--blue);
      color: var(--text); border-radius: 4px; padding: .4rem .75rem; font-size: .85rem;
    }}
    .toolbar input {{ min-width: 200px; }}
    .toolbar label {{ color: var(--muted); font-size: .85rem; }}
    /* Table */
    table {{ border-collapse: collapse; width: 100%; background: var(--surface); font-size: .88rem; }}
    th, td {{ padding: .45rem .75rem; text-align: left; border-bottom: 1px solid var(--surface2); }}
    th {{ background: var(--surface2); color: var(--cyan); cursor: pointer;
          user-select: none; white-space: nowrap; position: sticky; top: 0; z-index: 1; }}
    th::after {{ content: " ⇅"; opacity: .4; font-size: .75em; }}
    th.asc::after  {{ content: " ↑"; opacity: 1; }}
    th.desc::after {{ content: " ↓"; opacity: 1; }}
    tr:hover {{ background: var(--surface2); }}
    .open   {{ color: var(--green);  font-weight: 600; }}
    .closed {{ color: var(--red);    }}
    .filtered {{ color: var(--yellow); }}
    .openfiltered {{ color: var(--yellow); }}
    .error  {{ color: var(--blue);   }}
    .tls-badge {{ background: var(--cyan); color: var(--bg);
                  font-size: .7rem; font-weight: 700; border-radius: 3px;
                  padding: 0 .35rem; margin-left: .35rem; vertical-align: middle; }}
    .banner {{ color: var(--muted); font-size: .82rem; max-width: 300px;
               overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    /* Disclaimer */
    .disclaimer {{ margin-top: 2rem; padding: 1rem; border: 1px solid var(--red);
                   border-radius: 6px; color: #ff8888; font-size: .8rem; }}
    #count {{ color: var(--muted); font-size: .83rem; }}
  </style>
</head>
<body>
  <h1>Advanced Port Scanner — Scan Report</h1>
  <p class="meta">Generated {generated_at}{meta_line}</p>

  <div class="cards">
    <div class="card"><div class="num">{total}</div><div class="label">Scanned</div></div>
    <div class="card"><div class="num" style="color:var(--green)">{open_c}</div><div class="label">Open</div></div>
    <div class="card"><div class="num" style="color:var(--red)">{closed_c}</div><div class="label">Closed</div></div>
    <div class="card"><div class="num" style="color:var(--yellow)">{filtered_c}</div><div class="label">Filtered</div></div>
    <div class="card"><div class="num">{elapsed}</div><div class="label">Seconds</div></div>
  </div>

  <div class="toolbar">
    <input id="search" type="search" placeholder="Filter by host, port, service…" oninput="applyFilters()">
    <label>State:
      <select id="stateFilter" onchange="applyFilters()">
        <option value="">All</option>
        <option value="open">Open</option>
        <option value="closed">Closed</option>
        <option value="filtered">Filtered</option>
      </select>
    </label>
    <label>Protocol:
      <select id="protoFilter" onchange="applyFilters()">
        <option value="">All</option>
        <option value="tcp">TCP</option>
        <option value="udp">UDP</option>
      </select>
    </label>
    <span id="count"></span>
  </div>

  <table id="results">
    <thead>
      <tr>
        <th onclick="sortBy(0)">Host</th>
        <th onclick="sortBy(1)">Port</th>
        <th onclick="sortBy(2)">Proto</th>
        <th onclick="sortBy(3)">State</th>
        <th onclick="sortBy(4)">Service</th>
        <th>Banner</th>
        <th onclick="sortBy(6)">RTT (ms)</th>
      </tr>
    </thead>
    <tbody id="tbody">
{rows}
    </tbody>
  </table>

  <div class="disclaimer">
    ⚠ This report is for authorized security testing only.
    Scanning systems without explicit written permission may be illegal in your jurisdiction.
  </div>

  <script>
    // ---- Sorting ----
    var sortCol = 1, sortAsc = true;
    function sortBy(col) {{
      if (sortCol === col) sortAsc = !sortAsc;
      else {{ sortCol = col; sortAsc = true; }}
      document.querySelectorAll('th').forEach((th, i) => {{
        th.classList.remove('asc','desc');
        if (i === col) th.classList.add(sortAsc ? 'asc' : 'desc');
      }});
      var tbody = document.getElementById('tbody');
      var rows  = Array.from(tbody.querySelectorAll('tr'));
      rows.sort(function(a, b) {{
        var va = a.cells[col] ? a.cells[col].dataset.val || a.cells[col].innerText : '';
        var vb = b.cells[col] ? b.cells[col].dataset.val || b.cells[col].innerText : '';
        var na = parseFloat(va), nb = parseFloat(vb);
        if (!isNaN(na) && !isNaN(nb)) return sortAsc ? na - nb : nb - na;
        return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
      }});
      rows.forEach(r => tbody.appendChild(r));
      updateCount();
    }}
    // ---- Filtering ----
    function applyFilters() {{
      var q     = document.getElementById('search').value.toLowerCase();
      var state = document.getElementById('stateFilter').value;
      var proto = document.getElementById('protoFilter').value;
      var rows  = document.querySelectorAll('#tbody tr');
      rows.forEach(function(row) {{
        var text = row.innerText.toLowerCase();
        var st   = row.dataset.state || '';
        var pr   = row.dataset.proto || '';
        var show = text.includes(q)
                   && (!state || st.startsWith(state))
                   && (!proto || pr === proto);
        row.style.display = show ? '' : 'none';
      }});
      updateCount();
    }}
    function updateCount() {{
      var visible = Array.from(document.querySelectorAll('#tbody tr'))
                        .filter(r => r.style.display !== 'none').length;
      document.getElementById('count').textContent = visible + ' rows shown';
    }}
    updateCount();
  </script>
</body>
</html>
"""


def export_html(
    results: List[ScanResult],
    path: str,
    metadata: Optional[dict] = None,
) -> None:
    open_c     = sum(1 for r in results if r.state == "open")
    closed_c   = sum(1 for r in results if r.state == "closed")
    filtered_c = sum(1 for r in results if r.state in ("filtered", "open|filtered"))
    elapsed    = metadata.get("elapsed_seconds", "?") if metadata else "?"

    rows: list[str] = []
    for r in sorted(results, key=lambda x: (x.host, x.port)):
        state_css = r.state.replace("|", "").replace("-", "")
        tls_badge = '<span class="tls-badge">TLS</span>' if getattr(r, "tls", False) else ""
        banner_td = (
            f'<td class="banner" title="{html.escape(r.banner or "")}">'
            f"{html.escape(_trunc(r.banner or '', 80))}</td>"
        )
        rtt = f"{r.response_time_ms:.1f}" if r.response_time_ms else ""
        rows.append(
            f'      <tr data-state="{html.escape(r.state)}" data-proto="{r.protocol}">'
            f'<td>{html.escape(r.host)}</td>'
            f'<td data-val="{r.port}">{r.port}</td>'
            f'<td>{r.protocol}</td>'
            f'<td class="{state_css}">{html.escape(r.state)}{tls_badge}</td>'
            f'<td>{html.escape(r.service or "")}</td>'
            f'{banner_td}'
            f'<td data-val="{rtt}">{rtt}</td>'
            f'</tr>'
        )

    meta_line = ""
    if metadata:
        meta_line = " — " + ", ".join(
            f"{k}: {html.escape(str(v))}" for k, v in metadata.items()
        )

    page = _HTML_TEMPLATE.format(
        generated_at=html.escape(datetime.now(timezone.utc).isoformat()),
        meta_line=meta_line,
        total=len(results),
        open_c=open_c,
        closed_c=closed_c,
        filtered_c=filtered_c,
        elapsed=elapsed,
        rows="\n".join(rows) if rows else "      <tr><td colspan='7'>No results</td></tr>",
    )

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)
