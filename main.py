"""
__main__.py
-----------
Entry point for `python -m port_scanner`.
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
