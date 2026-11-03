"""Entry point for the packaged build.

PyInstaller cannot use ``python -m sweep``, so this script is the frozen
equivalent: it imports the GUI and hands over. Kept separate from sweep/ so the
package itself stays import-clean and testable without a build.
"""

import sys

from sweep.gui import main

if __name__ == "__main__":
    main(sys.argv[1:])
