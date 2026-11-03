"""Entry point for the packaged build.

PyInstaller cannot use ``python -m sweep``, so this script is the frozen
equivalent. With no arguments (or only options such as ``--elevated``) it opens
the window. With a subcommand - the scheduled task runs
``Sweep.exe clean --apply --quiet`` - it runs the command line instead, because
opening a window at 3 a.m. and cleaning nothing is what the scheduler used to
get. Kept separate from sweep/ so the package itself stays import-clean and
testable without a build.
"""

import os
import sys


def _streams_for_windowed_build() -> None:
    """A windowed exe has no console: give the command line somewhere to
    write, so its report and any error survive the run."""
    if sys.stdout is not None and sys.stderr is not None:
        return
    from sweep import base
    log_dir = os.path.join(base.state_dir(), "logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
        fh = open(os.path.join(log_dir, "last-command-line-run.log"), "w",
                  encoding="utf-8", buffering=1)
    except OSError:
        fh = open(os.devnull, "w", encoding="utf-8")
    if sys.stdout is None:
        sys.stdout = fh
    if sys.stderr is None:
        sys.stderr = fh


def run(argv: list[str]) -> int:
    if argv and not argv[0].startswith("-"):
        _streams_for_windowed_build()
        from sweep.cli import main as cli_main
        return int(cli_main(argv) or 0)
    from sweep.gui import main as gui_main
    gui_main(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
