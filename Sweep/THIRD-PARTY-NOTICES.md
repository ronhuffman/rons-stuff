# Third-party notices

Sweep's own code is released under the MIT licence (see `LICENSE`). Running it
from source needs only Python and its standard library.

The packaged build (`dist\Sweep`, made with `pyinstaller Sweep.spec`) also
contains software written by others. Each part is redistributed under its own
licence:

| Component | Where it is in the build | Licence |
| --- | --- | --- |
| Python 3.12 runtime and standard library | `python312.dll`, `base_library.zip`, `*.pyd`, the module archive inside `Sweep.exe` | PSF License Agreement for Python |
| Tcl/Tk 8.6 (the window toolkit) | `tcl86t.dll`, `tk86t.dll`, `_tcl_data\`, `_tk_data\` | Tcl/Tk licence (BSD-style) |
| OpenSSL 3 | `libcrypto-3.dll`, `libssl-3.dll` | Apache License 2.0 |
| SQLite | `sqlite3.dll` | Public domain |
| zlib | `zlib1.dll` | zlib licence |
| bzip2 | `_bz2.pyd` | bzip2 licence (BSD-style) |
| xz / liblzma | `_lzma.pyd` | Public domain / 0BSD, depending on version |
| libffi | `libffi-8.dll` | MIT |
| Expat | `pyexpat.pyd` | MIT |
| libmpdec | `_decimal.pyd` | BSD 2-Clause |
| Microsoft Visual C++ runtime and Universal C Runtime | `VCRUNTIME140.dll`, `ucrtbase.dll`, `api-ms-win-*.dll` | Microsoft redistributable-code terms |
| PyInstaller bootloader | the launcher part of `Sweep.exe` | GPL 2.0 or later with the PyInstaller bootloader exception, which permits distributing it inside programs under any licence |
| PyInstaller run-time hooks | inside the module archive (`pyi_rth_*`) | Apache License 2.0 |

## Full licence texts

* `licenses\python\LICENSE.txt` is copied, at build time, from the Python
  installation used to make the build. It holds the Python licence, the terms
  for the Microsoft runtime, and the licences of bzip2, libffi, OpenSSL (Apache
  2.0) and Tcl/Tk. `Sweep.spec` refuses to build if that file is missing.
* `licenses\python\python-3.12-incorporated-software.txt` is Python's own list of
  licences for code built into it - including expat and libmpdec, which the file
  above does not cover - copied from the Python 3.12.10 documentation. The
  source copy is `licenses\` in this repository.
* SQLite and liblzma (xz) are in the public domain (newer xz releases use 0BSD);
  neither requires a notice.
* PyInstaller's licence, including the bootloader exception:
  <https://github.com/pyinstaller/pyinstaller/blob/develop/COPYING.txt>

## Trademarks

Sweep is not affiliated with or endorsed by Piriform or Gen Digital. CCleaner is
their trademark and is named only to describe compatibility (Sweep can read the
cleaning rules of a CCleaner installation already on the same PC).
