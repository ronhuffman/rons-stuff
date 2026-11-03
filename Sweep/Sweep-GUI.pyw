"""Double-click launcher for the Sweep GUI (no console window)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sweep.gui import main

if __name__ == "__main__":
    main()
