"""
progress.py
------------
A tiny, dependency-free progress bar for the console. Thread-safe enough
for our purposes (a single lock guards the redraw).
"""

from __future__ import annotations

import sys
import threading
import time


class ProgressBar:
    """Simple single-line progress bar: [#####.....] 42% (420/1000) 12.3/s"""

    def __init__(self, total: int, label: str = "Scanning", width: int = 30, enabled: bool = True):
        self.total = max(total, 1)
        self.label = label
        self.width = width
        self.enabled = enabled and sys.stdout.isatty()
        self._count = 0
        self._lock = threading.Lock()
        self._start = time.time()
        self._done = False

    def update(self, increment: int = 1) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._count += increment
            self._render()

    def _render(self) -> None:
        frac = min(self._count / self.total, 1.0)
        filled = int(self.width * frac)
        bar = "#" * filled + "-" * (self.width - filled)
        elapsed = max(time.time() - self._start, 1e-6)
        rate = self._count / elapsed
        sys.stdout.write(
            f"\r{self.label}: [{bar}] {frac * 100:5.1f}% "
            f"({self._count}/{self.total}) {rate:6.1f}/s"
        )
        sys.stdout.flush()

    def finish(self) -> None:
        if not self.enabled or self._done:
            return
        self._done = True
        with self._lock:
            self._count = self.total
            self._render()
            sys.stdout.write("\n")
            sys.stdout.flush()
