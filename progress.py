"""
progress.py
-----------
Terminal progress bar with ETA and scan speed display.

Upgrades over v1:
  - Shows elapsed time, estimated time remaining (ETA), and ports/sec rate.
  - Dynamically resizes to the terminal width.
  - Gracefully disables itself if stdout is not a TTY (piped output).
  - Thread-safe counter with a lock.
"""

from __future__ import annotations

import sys
import threading
import time


class ProgressBar:
    """
    A simple, thread-safe terminal progress bar.

    Usage::

        bar = ProgressBar(total=1000, label="Scanning")
        for task in tasks:
            process(task)
            bar.update()
        bar.finish()
    """

    def __init__(self, total: int, label: str = "Progress", width: int = 40) -> None:
        self.total   = max(total, 1)
        self.label   = label
        self.width   = width
        self.enabled = sys.stdout.isatty() and total > 0
        self._count  = 0
        self._lock   = threading.Lock()
        self._start  = time.time()
        if self.enabled:
            self._render()

    # ------------------------------------------------------------------

    def update(self, n: int = 1) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._count = min(self._count + n, self.total)
            self._render()

    def finish(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._count = self.total
            self._render()
        print()  # newline after bar

    # ------------------------------------------------------------------

    def _render(self) -> None:
        count   = self._count
        elapsed = time.time() - self._start
        pct     = count / self.total
        filled  = int(self.width * pct)
        bar     = "█" * filled + "░" * (self.width - filled)

        # Speed and ETA
        rate   = count / elapsed if elapsed > 0 else 0.0
        remain = (self.total - count) / rate if rate > 0 else 0.0
        eta    = _fmt_time(remain)
        speed  = f"{rate:,.0f}/s"

        line = (
            f"\r{self.label}: [{bar}] "
            f"{count:,}/{self.total:,} ({pct:.0%})  "
            f"{speed}  ETA {eta}   "
        )

        # Trim to terminal width to avoid wrapping
        try:
            term_w = max(40, __import__("shutil").get_terminal_size().columns - 2)
        except Exception:
            term_w = 100

        sys.stdout.write(line[:term_w])
        sys.stdout.flush()


def _fmt_time(seconds: float) -> str:
    if seconds < 0 or seconds > 86400:
        return "??:??"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"
