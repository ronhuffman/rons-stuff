"""
Sweep - disk usage analysis.

This is the part a cleaner normally omits. Knowing that 41 GB of "other" is
sitting in one folder is worth more than any registry key, so Sweep ships a
treemap, a largest-file finder and a duplicate finder.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass, field

from . import base


@dataclass
class Node:
    name: str
    path: str
    size: int = 0
    is_dir: bool = True
    children: list["Node"] = field(default_factory=list)
    file_count: int = 0
    truncated: bool = False        # some children omitted to bound the tree
    #: Entries that could not be read at all. A node with denied > 0 and a size
    #: of 0 was not measured - it is not an empty folder.
    denied: int = 0


def disk_usage(path: str) -> tuple[int, int, int] | None:
    """(total, used, free) for the volume holding *path*, or None if unmeasurable.

    Returning (0, 0, 0) made an unreadable volume print as "0 B used (0 B free)",
    which reads as a real measurement.
    """
    try:
        return shutil.disk_usage(path)
    except OSError:
        return None


def _entry_size(entry: os.DirEntry) -> int:
    try:
        return entry.stat(follow_symlinks=False).st_size
    except OSError:
        return 0


def build_tree(root: str, max_depth: int = 3, max_children: int = 14,
               cancel: base.Cancel | None = None, progress=None) -> Node:
    """Aggregate sizes under *root* into a bounded tree.

    Children below ``max_children`` are folded into an "(other)" node so the
    totals always add up and the UI never has to render thousands of slivers.
    """
    root = os.path.abspath(root)

    def walk(path: str, depth: int) -> Node:
        node = Node(name=os.path.basename(path) or path, path=path)
        try:
            entries = list(os.scandir(path))
        except OSError:
            node.denied = 1           # could not read, not empty
            return node

        kids: list[Node] = []
        other_size = 0
        other_files = 0
        for entry in entries:
            if cancel is not None and cancel.is_set():
                return node
            try:
                if entry.is_symlink() or base.is_reparse(entry.path):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth < max_depth:
                        child = walk(entry.path, depth + 1)
                    else:
                        child = Node(name=entry.name, path=entry.path)
                        child.size, child.file_count = _deep_size(entry.path, cancel)
                    kids.append(child)
                    node.size += child.size
                    node.file_count += child.file_count
                elif entry.is_file(follow_symlinks=False):
                    size = _entry_size(entry)
                    kids.append(Node(name=entry.name, path=entry.path, size=size, is_dir=False))
                    node.size += size
                    node.file_count += 1
                else:
                    continue
            except OSError:
                node.denied += 1      # could not be stat'ed, not zero bytes
                continue

        kids.sort(key=lambda n: n.size, reverse=True)
        if len(kids) > max_children:
            head = kids[:max_children - 1]
            tail = kids[max_children - 1:]
            other_size = sum(n.size for n in tail)
            other_files = sum(n.file_count for n in tail)
            head.append(Node(
                name=f"({len(tail)} more)", path=path, size=other_size,
                is_dir=False, file_count=other_files,
            ))
            node.truncated = True
            kids = head
        node.children = kids
        if progress:
            progress(path, node.size)
        return node

    return walk(root, 0)


def _deep_size(path: str, cancel: base.Cancel | None = None) -> tuple[int, int]:
    total = 0
    files = 0
    for _p, size in base.walk(path, "*", recurse=True):
        if cancel is not None and cancel.is_set():
            break
        total += size
        files += 1
    return total, files


def largest_files(root: str, limit: int = 40, min_size: int = 1 << 20,
                  cancel: base.Cancel | None = None, progress=None) -> list[tuple[str, int]]:
    """Top *limit* files by size. Keeps a bounded heap rather than sorting
    every file on a multi-million-file volume."""
    import heapq
    heap: list[tuple[int, str]] = []
    scanned = 0
    for path, size in base.walk(root, "*", recurse=True):
        if cancel is not None and cancel.is_set():
            break
        scanned += 1
        if scanned % 20000 == 0 and progress:
            progress(scanned, path)
        if size < min_size:
            continue
        if len(heap) < limit:
            heapq.heappush(heap, (size, path))
        elif size > heap[0][0]:
            heapq.heapreplace(heap, (size, path))
    out = sorted(((p, s) for s, p in heap), key=lambda t: -t[1])
    return out


def find_duplicates(root: str, min_size: int = 1 << 20, limit_groups: int = 200,
                    cancel: base.Cancel | None = None, progress=None) -> list[list[tuple[str, int]]]:
    """Group identical files by (size, content hash).

    Three passes keep this cheap on big volumes: buckets by size first (no
    hashing), then a 64 KiB prefix hash, then a full hash only for candidates
    that already matched on size and prefix.
    """
    by_size: dict[int, list[str]] = {}
    for path, size in base.walk(root, "*", recurse=True):
        if cancel is not None and cancel.is_set():
            return []
        if size < min_size:
            continue
        by_size.setdefault(size, []).append(path)

    candidates = {s: paths for s, paths in by_size.items() if len(paths) > 1}
    if not candidates:
        return []

    def prefix_hash(path: str) -> str | None:
        h = hashlib.blake2b(digest_size=16)
        try:
            with open(path, "rb") as fh:
                h.update(fh.read(65536))
            return h.hexdigest()
        except OSError:
            return None

    def full_hash(path: str) -> str | None:
        h = hashlib.blake2b(digest_size=32)
        try:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(1 << 20)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    done = 0
    total = sum(len(v) for v in candidates.values())
    groups: list[list[tuple[str, int]]] = []
    for size, paths in candidates.items():
        by_prefix: dict[str, list[str]] = {}
        for p in paths:
            if cancel is not None and cancel.is_set():
                return groups
            done += 1
            if progress and done % 200 == 0:
                progress(done, total, p)
            ph = prefix_hash(p)
            if ph:
                by_prefix.setdefault(ph, []).append(p)
        for _ph, plist in by_prefix.items():
            if len(plist) < 2:
                continue
            by_full: dict[str, list[str]] = {}
            for p in plist:
                fh_ = full_hash(p)
                if fh_:
                    by_full.setdefault(fh_, []).append(p)
            for _fh, flist in by_full.items():
                if len(flist) > 1:
                    groups.append([(p, size) for p in flist])
                    if len(groups) >= limit_groups:
                        groups.sort(key=lambda g: -g[0][1] * (len(g) - 1))
                        return groups
    groups.sort(key=lambda g: -g[0][1] * (len(g) - 1))
    return groups


# --------------------------------------------------------------------------
# treemap layout (squarified)
# --------------------------------------------------------------------------

def squarify(items: list[tuple[str, float]], x: float, y: float,
             w: float, h: float) -> list[tuple[str, float, float, float, float]]:
    """Lay out (label, value) pairs into rectangles that fill the given box.

    Returns (label, x, y, width, height). Values must be positive; zero/negative
    entries are dropped so the geometry never degenerates.
    """
    vals = [(lbl, float(v)) for lbl, v in items if v and v > 0]
    if not vals or w <= 0 or h <= 0:
        return []
    total = sum(v for _, v in vals)
    if total <= 0:
        return []
    scale = (w * h) / total
    rects: list[tuple[str, float, float, float, float]] = []

    def worst(row: list[tuple[str, float]], length: float) -> float:
        s = sum(v for _, v in row) * scale
        if s <= 0 or length <= 0:
            return float("inf")
        mx = max(v for _, v in row) * scale
        mn = min(v for _, v in row) * scale
        return max((length * length * mx) / (s * s), (s * s) / (length * length * mn))

    def layout(items_: list[tuple[str, float]], cx: float, cy: float, cw: float, ch: float):
        if not items_:
            return
        if len(items_) == 1:
            lbl, v = items_[0]
            rects.append((lbl, cx, cy, cw, ch))
            return
        row: list[tuple[str, float]] = []
        i = 0
        length = min(cw, ch)
        while i < len(items_):
            if not row:
                row.append(items_[i]); i += 1
                continue
            trial = row + [items_[i]]
            if worst(trial, length) <= worst(row, length):
                row = trial; i += 1
            else:
                break
        row_sum = sum(v for _, v in row) * scale
        rest = items_[i:]
        if cw >= ch:
            # vertical strip on the left
            rw = row_sum / ch if ch else 0
            oy = cy
            for lbl, v in row:
                rh = (v * scale) / rw if rw else 0
                rects.append((lbl, cx, oy, rw, rh))
                oy += rh
            layout(rest, cx + rw, cy, cw - rw, ch)
        else:
            rh = row_sum / cw if cw else 0
            ox = cx
            for lbl, v in row:
                rw = (v * scale) / rh if rh else 0
                rects.append((lbl, ox, cy, rw, rh))
                ox += rw
            layout(rest, cx, cy + rh, cw, ch - rh)

    layout(vals, x, y, w, h)
    return rects
