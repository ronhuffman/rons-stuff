"""
Sweep - secure erase.

Two operations:

* ``wipe_file``  - overwrite a file's bytes, then unlink it.
* ``wipe_free_space`` - write random data into new files until the volume is
  full, then delete them, so previously-deleted data is overwritten.

Honest limitation, stated in the UI too: on an SSD with wear levelling, on a
copy-on-write filesystem, or inside a VM's thin-provisioned disk, overwriting a
logical file does **not** guarantee the old physical blocks are gone. Only
full-disk encryption (BitLocker) plus key destruction, or an ATA Secure Erase,
actually achieves that. A software cleaner cannot promise it, and any tool that
does is overselling.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import sys
from dataclasses import dataclass

from . import base

CHUNK = 1 << 20                    # 1 MiB


@dataclass
class WipeResult:
    path: str
    size: int
    passes: int
    ok: bool
    error: str = ""


def _patterns(passes: int) -> list[bytes | None]:
    """Byte patterns for each pass. ``None`` means cryptographic random."""
    if passes <= 1:
        return [None]
    if passes == 2:
        return [b"\x00", None]
    # 3-pass: zeros, ones, random (the shape of DoD 5220.22-M without the
    # verification pass, which we cannot honestly complete through the OS cache)
    return [b"\x00", b"\xff", None][:passes]


def wipe_file(path: str, passes: int = 1) -> WipeResult:
    """Overwrite then delete one file."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return WipeResult(path, 0, passes, False, str(exc))

    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        return WipeResult(path, size, passes, False, str(exc))

    try:
        with os.fdopen(fd, "r+b", buffering=0) as fh:
            for pat in _patterns(passes):
                fh.seek(0)
                remaining = size
                while remaining > 0:
                    n = min(CHUNK, remaining)
                    fh.write(os.urandom(n) if pat is None else pat * n)
                    remaining -= n
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
        os.unlink(path)
        return WipeResult(path, size, passes, True)
    except OSError as exc:
        return WipeResult(path, size, passes, False, str(exc))


def wipe_free_space(root: str, max_bytes: int | None = None,
                    cancel: base.Cancel | None = None,
                    progress=None) -> tuple[int, int, str]:
    """Fill the volume's free space with random files, then remove them.

    Returns (bytes_written, files_written, note).
    """
    root = os.path.abspath(root)
    try:
        total, used, free = shutil.disk_usage(root)
    except OSError as exc:
        return 0, 0, f"cannot measure {root}: {exc}"

    # Leave 512 MiB untouched so the volume never actually fills up.
    budget = max(0, free - (512 << 20))
    if max_bytes is not None:
        budget = min(budget, max_bytes)
    if budget <= 0:
        return 0, 0, "not enough free space to make wiping worthwhile"

    written = files = 0
    folder = os.path.join(root, ".sweep-wipe")
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError as exc:
        return 0, 0, f"cannot create {folder}: {exc}"

    try:
        while written < budget:
            if cancel is not None and cancel.is_set():
                break
            size = min(64 << 20, budget - written)
            path = os.path.join(folder, f"wipe-{files:06d}.bin")
            try:
                with open(path, "wb", buffering=0) as fh:
                    remaining = size
                    while remaining > 0:
                        n = min(CHUNK, remaining)
                        fh.write(os.urandom(n))
                        remaining -= n
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                break                        # disk full or permission -> stop
            written += size
            files += 1
            if progress:
                progress(written, budget)
    finally:
        removed = 0
        try:
            for entry in os.scandir(folder):
                try:
                    os.unlink(entry.path)
                    removed += 1
                except OSError:
                    pass
            os.rmdir(folder)
        except OSError:
            pass
    return written, files, (f"overwrote {files} file(s), {base.human(written)}; "
                            f"removed {removed}")


def is_ssd(path: str) -> bool | None:
    """Best-effort SSD detection, used only to word the caveat honestly."""
    if not base.IS_WINDOWS:
        return None
    try:
        import subprocess
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-PhysicalDisk | Select-Object -First 1 -ExpandProperty MediaType)"],
            capture_output=True, text=True, timeout=15,
            creationflags=0x08000000,
        ).stdout.strip().lower()
        if "ssd" in out:
            return True
        if "hdd" in out:
            return False
    except Exception:
        pass
    return None
