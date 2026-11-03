# -*- mode: python ; coding: utf-8 -*-
import os
import sys

# The licence of the Python this build bundles. It covers Python and the
# libraries the python.org Windows build ships with (OpenSSL, Tcl/Tk, SQLite,
# zlib, bzip2, xz, libffi, expat, mpdecimal, the Microsoft runtime). Their
# licences require the notices to travel with the program, so a build without
# them is refused rather than shipped.
PY_LICENSE = os.path.join(sys.base_prefix, 'LICENSE.txt')
if not os.path.isfile(PY_LICENSE):
    raise SystemExit(f"Python licence not found at {PY_LICENSE} - refusing to build "
                     "a binary without its third-party notices")


a = Analysis(
    ['tools\\pyinstaller_entry.py'],
    pathex=['.'],
    binaries=[],
    datas=[('docs\\icon.png', 'docs'),
           ('LICENSE', '.'),
           ('THIRD-PARTY-NOTICES.md', '.'),
           (PY_LICENSE, 'licenses\\python')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Sweep',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['docs\\sweep.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Sweep',
)
