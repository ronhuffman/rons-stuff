"""
Sweep - graphical interface (tkinter, standard library only).

Layout: a sidebar on the left switches between pages (Clean, Space, Startup,
Health and the Tools pages); a slim status bar runs along the bottom. Every
page has the same shape - a title with a one-line explanation, a row of
controls, then the content in a card.

Threading model: all scanning/cleaning happens on a worker thread; results are
handed back through a queue and applied on the Tk main thread via after().
Nothing in the UI ever blocks on I/O.
"""

from __future__ import annotations

import ctypes
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import traceback
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

from . import __version__, analyzer, base, cleaner, config, rules, scanner, system

# --------------------------------------------------------------------------
# look and feel
# --------------------------------------------------------------------------

COL_BG = "#14161b"          # page background
COL_SIDE = "#0f1115"        # sidebar and status bar
COL_PANEL = "#1b1e25"       # cards and tables
COL_ROW_ALT = "#23272f"     # table striping - visible, not loud
COL_HEAD = "#22262e"        # table headings
COL_FIELD = "#252a33"       # text entry
COL_BTN = "#2a2f39"
COL_BTN_HOVER = "#353b47"
COL_NAV_ACTIVE = "#1d212a"
COL_NAV_HOVER = "#171a20"
COL_FG = "#e6e8ec"
COL_MUTED = "#8b93a1"
COL_SUBTLE = "#5d6471"
COL_ACCENT = "#4f9dff"
COL_ACCENT_HOVER = "#6cadff"
COL_ON_ACCENT = "#06101f"
COL_SEL = "#25385a"
COL_LINE = "#2a2e37"
COL_THUMB = "#3a404c"
COL_TIP = "#2b303a"         # hover tooltip
COL_WARN_BG = "#2b2517"     # amber notice strip
COL_GREEN = "#57c98a"
COL_AMBER = "#e8b44a"
COL_RED = "#e2696f"
RISK_COLOR = {"safe": COL_GREEN, "moderate": COL_AMBER, "caution": COL_RED}

# Text glyphs kept for anything that still refers to them; the lists themselves
# now draw real checkbox images.
CHECK_ON = "\u2611"
CHECK_OFF = "\u2610"
CHECKED, UNCHECKED = CHECK_ON, CHECK_OFF

PADX = 24          # page side padding
PADY = 10

# Physical-pixel scale factor for this display (1.0 at 96 dpi).
S = 1.0

# Resolved once a Tk root exists (see _init_fonts).
UI_FONT = "Segoe UI"
UI_SEMI = "Segoe UI Semibold"
ICON_FONT = ""     # "Segoe Fluent Icons" / "Segoe MDL2 Assets" when installed

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICON_PNG = os.path.join(_ROOT, "docs", "icon.png")
ICON_SMALL_PNG = os.path.join(_ROOT, "docs", "icon-64.png")

# Sidebar icons (Segoe MDL2 Assets / Segoe Fluent Icons code points).
ICONS = {
    "clean": "\uE74D",        # Delete
    "space": "\uEDA2",        # HardDrive
    "startup": "\uE7E8",      # PowerButton
    "health": "\uE90F",       # Repair
    "Updates": "\uE895",      # Sync
    "Applications": "\uE71D",  # AllApps
    "Drivers": "\uE772",      # Devices
    "Automatic cleaning": "\uE787",   # Calendar
    "Secure erase": "\uE72E",  # Lock
    "Cookie keep-list": "\uE774",     # Globe
    "settings": "\uE713",     # Settings
}


def px(n: float) -> int:
    """Scale a logical pixel measurement for the current display DPI."""
    return max(1, int(round(n * S)))


def f(size: int, bold: bool = False) -> tuple:
    """A UI font tuple. Semibold on Windows, bold elsewhere."""
    if bold:
        return (UI_SEMI, size) if UI_SEMI else (UI_FONT, size, "bold")
    return (UI_FONT, size)


def _init_fonts(root: tk.Misc) -> None:
    global UI_FONT, UI_SEMI, ICON_FONT
    try:
        fams = set(tkfont.families(root))
    except tk.TclError:
        return
    if "Segoe UI" in fams:
        UI_FONT = "Segoe UI"
        UI_SEMI = "Segoe UI Semibold" if "Segoe UI Semibold" in fams else ""
    else:
        try:
            UI_FONT = tkfont.Font(root=root, name="TkDefaultFont", exists=True).actual("family")
        except tk.TclError:
            UI_FONT = "TkDefaultFont"
        UI_SEMI = ""
    ICON_FONT = ""
    for cand in ("Segoe Fluent Icons", "Segoe MDL2 Assets"):
        if cand in fams:
            ICON_FONT = cand
            break
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
        try:
            tkfont.Font(root=root, name=name, exists=True).configure(family=UI_FONT, size=10)
        except tk.TclError:
            pass


def enable_dpi_awareness() -> None:
    """Without this Windows bitmap-stretches the window on a HiDPI display,
    which looks blurry and makes Tk's coordinate system disagree with the
    screen. Must run before the Tk root is created."""
    if os.name != "nt":
        return
    try:
        # PROCESS_PER_MONITOR_DPI_AWARE
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _dark_title_bar(win: tk.Tk) -> None:
    """Ask Windows for a dark title bar so the frame matches the app, and on
    Windows 11 colour the caption like the sidebar. Silently does nothing where
    the attribute is not supported."""
    if os.name != "nt":
        return
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        dwm = ctypes.windll.dwmapi
        on = ctypes.c_int(1)
        # 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (19 on builds before 20H1)
        for attr in (20, 19):
            if dwm.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(on),
                                         ctypes.sizeof(on)) == 0:
                break
        r, g, b = (int(COL_SIDE[i:i + 2], 16) for i in (1, 3, 5))
        colour = ctypes.c_int(r | (g << 8) | (b << 16))
        dwm.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(colour),   # CAPTION_COLOR
                                  ctypes.sizeof(colour))
    except Exception:
        pass


# --------------------------------------------------------------------------
# small images drawn at runtime: checkboxes and status dots
# --------------------------------------------------------------------------

_IMAGES: dict[int, tuple] = {}


def _draw_box(img: tk.PhotoImage, x0: int, n: int, state: str) -> None:
    """A checkbox: hollow when off, filled accent with a tick (or dash) when on.
    'disoff' / 'dison' are the dimmed versions for disabled controls."""
    if state in ("off", "disoff"):
        c = "#6b7280" if state == "off" else "#3a3f4a"
        img.put(c, to=(x0 + 1, 0, x0 + n - 1, 1))
        img.put(c, to=(x0 + 1, n - 1, x0 + n - 1, n))
        img.put(c, to=(x0, 1, x0 + 1, n - 1))
        img.put(c, to=(x0 + n - 1, 1, x0 + n, n - 1))
        return
    fill = COL_ACCENT if state != "dison" else "#2c3b52"
    img.put(fill, to=(x0 + 1, 0, x0 + n - 1, n))
    img.put(fill, to=(x0, 1, x0 + n, n - 1))
    ink = COL_ON_ACCENT if state != "dison" else "#7a889e"
    t = max(2, round(n / 8))
    if state == "mixed":
        y = n // 2 - t // 2
        img.put(ink, to=(x0 + n // 4, y, x0 + n - n // 4, y + t))
        return
    pts = [(0.20, 0.50), (0.41, 0.71), (0.80, 0.29)]
    for (ax, ay), (bx, by) in zip(pts, pts[1:]):
        steps = n * 3
        for i in range(steps + 1):
            u = i / steps
            ix = int(x0 + (ax + (bx - ax) * u) * n)
            iy = int((ay + (by - ay) * u) * n)
            img.put(ink, to=(ix, iy, min(ix + t, x0 + n), min(iy + t, n)))


def _draw_dot(img: tk.PhotoImage, cx: float, cy: float, r: float, color: str,
              hollow: bool = False) -> None:
    for y in range(int(cy - r) - 1, int(cy + r) + 2):
        for x in range(int(cx - r) - 1, int(cx + r) + 2):
            if x < 0 or y < 0:
                continue
            d = ((x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2) ** 0.5
            if (r - 1.4 <= d <= r) if hollow else (d <= r):
                try:
                    img.put(color, to=(x, y))
                except tk.TclError:
                    pass


def _make_image(widget: tk.Misc, key: str) -> tk.PhotoImage:
    kind, _, arg = key.partition(":")
    box = px(15)
    if kind == "box":
        im = tk.PhotoImage(master=widget, width=box, height=box)
        _draw_box(im, 0, box, arg)
    elif kind == "boxdot":                     # checkbox + risk dot
        state, _, risk = arg.partition(":")
        dot, gap = px(8), px(9)
        im = tk.PhotoImage(master=widget, width=box + gap + dot, height=box)
        _draw_box(im, 0, box, state)
        _draw_dot(im, box + gap + dot / 2, box / 2, dot / 2,
                  RISK_COLOR.get(risk, COL_MUTED))
    elif kind in ("dot", "ring"):
        im = tk.PhotoImage(master=widget, width=box, height=box)
        _draw_dot(im, box / 2, box / 2, px(9) / 2, arg, hollow=(kind == "ring"))
    else:
        im = tk.PhotoImage(master=widget, width=1, height=1)
    return im


def _img(widget: tk.Misc, key: str) -> tk.PhotoImage:
    """Cached per Tk interpreter (each Tk() root is its own interpreter)."""
    interp = widget.tk
    slot = _IMAGES.get(id(interp))
    if slot is None or slot[0] is not interp:
        slot = (interp, {})
        _IMAGES[id(interp)] = slot
    cache = slot[1]
    im = cache.get(key)
    if im is None:
        im = cache[key] = _make_image(widget, key)
    return im


# --------------------------------------------------------------------------
# async helper
# --------------------------------------------------------------------------

class Worker:
    """Runs one background job at a time and delivers callbacks on the UI thread."""

    def __init__(self, widget: tk.Misc) -> None:
        self.widget = widget
        self.q: queue.Queue = queue.Queue()
        self.cancel = base.Cancel()
        self._busy = False

    @property
    def busy(self) -> bool:
        return self._busy

    def start(self, fn, on_progress=None, on_done=None, on_error=None) -> None:
        if self._busy:
            return
        self._busy = True
        self._notify(True)
        self.cancel = base.Cancel()

        def target():
            try:
                result = fn(self.cancel, lambda *a: self.q.put(("progress", a)))
                self.q.put(("done", result))
            except BaseException as exc:              # noqa: BLE001 - surfaced in UI
                self.q.put(("error", (exc, traceback.format_exc())))

        threading.Thread(target=target, daemon=True).start()
        self._poll(on_progress, on_done, on_error)

    def _poll(self, on_progress, on_done, on_error) -> None:
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "progress":
                    if on_progress:
                        on_progress(*payload)
                elif kind == "done":
                    self._busy = False
                    self._notify(False)
                    if on_done:
                        on_done(payload)
                    return
                elif kind == "error":
                    self._busy = False
                    self._notify(False)
                    exc, tb = payload
                    if on_error:
                        on_error(exc, tb)
                    return
        except queue.Empty:
            pass
        self.widget.after(80, lambda: self._poll(on_progress, on_done, on_error))

    def _notify(self, busy: bool) -> None:
        """Tell the top-level window to show a busy cursor, if it supports it."""
        try:
            fn = getattr(self.widget.winfo_toplevel(), "set_busy", None)
            if fn:
                fn(busy)
        except Exception:
            pass


# --------------------------------------------------------------------------
# theme
# --------------------------------------------------------------------------

def _stripe(tree: ttk.Treeview) -> None:
    """Alternating row backgrounds; tags only set background so foreground tags
    (risk / status) still apply."""
    tree.tag_configure("odd", background=COL_ROW_ALT)
    tree.tag_configure("even", background=COL_PANEL)


def _flat(style: ttk.Style, name: str, bg: str, fg: str, hover: str,
          disabled_bg: str | None = None, disabled_fg: str = COL_SUBTLE,
          font=None, padding=None) -> None:
    """A borderless button style: clam draws bevels from bordercolor,
    lightcolor and darkcolor, so all three follow the background."""
    style.configure(name, background=bg, foreground=fg, bordercolor=bg,
                    lightcolor=bg, darkcolor=bg, relief="flat", borderwidth=0,
                    focusthickness=0, font=font or f(10), width=0,
                    padding=padding or (px(14), px(7)))
    dis = disabled_bg or bg
    states = [("disabled", dis), ("pressed", hover), ("active", hover)]
    style.map(name, background=states, bordercolor=states, lightcolor=states,
              darkcolor=states, foreground=[("disabled", disabled_fg)])


def _style(root: tk.Tk) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    root.configure(bg=COL_BG)
    style.configure(".", background=COL_BG, foreground=COL_FG, fieldbackground=COL_FIELD,
                    bordercolor=COL_LINE, lightcolor=COL_BG, darkcolor=COL_BG,
                    troughcolor=COL_PANEL, selectbackground=COL_SEL,
                    selectforeground=COL_FG, insertcolor=COL_FG, borderwidth=0,
                    font=f(10))

    # frames and labels
    style.configure("TFrame", background=COL_BG)
    style.configure("Card.TFrame", background=COL_PANEL)
    style.configure("Panel.TFrame", background=COL_PANEL)
    style.configure("TLabel", background=COL_BG, foreground=COL_FG, font=f(10))
    style.configure("Muted.TLabel", background=COL_BG, foreground=COL_MUTED)
    style.configure("Subtle.TLabel", background=COL_BG, foreground=COL_SUBTLE, font=f(9))
    style.configure("Title.TLabel", background=COL_BG, foreground=COL_FG, font=f(18, True))
    style.configure("Big.TLabel", background=COL_BG, foreground=COL_FG, font=f(20, True))
    style.configure("Head.TLabel", background=COL_BG, foreground=COL_FG, font=f(11, True))
    style.configure("Card.TLabel", background=COL_PANEL, foreground=COL_FG)
    style.configure("CardMuted.TLabel", background=COL_PANEL, foreground=COL_MUTED)
    style.configure("CardHead.TLabel", background=COL_PANEL, foreground=COL_FG,
                    font=f(11, True))
    style.configure("Hero.TLabel", background=COL_PANEL, foreground=COL_FG,
                    font=f(26, True))
    style.configure("Score.TLabel", background=COL_PANEL, foreground=COL_FG,
                    font=f(34, True))

    # buttons - one layout without the dotted focus ring, shared by every variant
    style.layout("TButton", [("Button.border", {"sticky": "nswe", "border": "1", "children": [
        ("Button.padding", {"sticky": "nswe", "children": [
            ("Button.label", {"sticky": "nswe"})]})]})])
    _flat(style, "TButton", COL_BTN, COL_FG, COL_BTN_HOVER, disabled_bg="#20232a")
    _flat(style, "Accent.TButton", COL_ACCENT, COL_ON_ACCENT, COL_ACCENT_HOVER,
          disabled_bg="#22324a", disabled_fg="#6a7f9e", font=f(10, True))
    _flat(style, "Link.TButton", COL_BG, COL_ACCENT, COL_BG,
          padding=(px(6), px(3)))
    style.map("Link.TButton", foreground=[("disabled", COL_SUBTLE),
                                          ("active", COL_ACCENT_HOVER)])
    _flat(style, "Seg.TButton", COL_PANEL, COL_MUTED, COL_NAV_ACTIVE,
          padding=(px(14), px(6)))
    style.map("Seg.TButton", foreground=[("active", COL_FG)])
    _flat(style, "SegOn.TButton", COL_BTN, COL_FG, COL_BTN, padding=(px(14), px(6)),
          font=f(10, True))

    # checkbuttons - the same drawn checkbox the lists use, and no focus ring
    indicator = "Checkbutton.indicator"
    try:
        style.element_create(
            "Sweep.Checkbutton.indicator", "image", _img(root, "box:off"),
            ("disabled", "selected", _img(root, "box:dison")),
            ("disabled", _img(root, "box:disoff")),
            ("selected", _img(root, "box:on")),
            width=px(15) + px(8), sticky="w")
        indicator = "Sweep.Checkbutton.indicator"
    except tk.TclError:
        pass
    style.layout("TCheckbutton", [("Checkbutton.padding", {"sticky": "nswe", "children": [
        (indicator, {"side": "left", "sticky": ""}),
        ("Checkbutton.label", {"side": "left", "sticky": "nswe"})]})])
    for name, bg in (("TCheckbutton", COL_BG), ("Card.TCheckbutton", COL_PANEL)):
        style.configure(name, background=bg, foreground=COL_FG, padding=(0, px(2)),
                        indicatorbackground=COL_FIELD, indicatorforeground=COL_ON_ACCENT,
                        upperbordercolor="#4b5262", lowerbordercolor="#4b5262",
                        indicatormargin=(0, 0, px(8), 0), focusthickness=0)
        style.map(name, background=[("active", bg)],
                  foreground=[("disabled", COL_SUBTLE)],
                  indicatorbackground=[("selected", COL_ACCENT), ("active", "#2c323d")],
                  upperbordercolor=[("selected", COL_ACCENT)],
                  lowerbordercolor=[("selected", COL_ACCENT)])

    # tables
    style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    style.layout("Treeview.Item", [("Treeitem.padding", {"sticky": "nswe", "children": [
        ("Treeitem.indicator", {"side": "left", "sticky": ""}),
        ("Treeitem.image", {"side": "left", "sticky": ""}),
        ("Treeitem.text", {"side": "left", "sticky": ""})]})])
    style.configure("Treeview", background=COL_PANEL, fieldbackground=COL_PANEL,
                    foreground=COL_FG, rowheight=px(28), borderwidth=0,
                    bordercolor=COL_PANEL, lightcolor=COL_PANEL, darkcolor=COL_PANEL,
                    indent=px(20), font=f(10))
    style.map("Treeview", background=[("selected", COL_SEL)],
              foreground=[("selected", "#ffffff")])
    style.configure("Treeview.Heading", background=COL_HEAD, foreground=COL_MUTED,
                    relief="flat", borderwidth=0, bordercolor=COL_HEAD,
                    lightcolor=COL_HEAD, darkcolor=COL_HEAD,
                    padding=(px(8), px(7)), font=f(9, True))
    style.map("Treeview.Heading", background=[("active", COL_HEAD)],
              lightcolor=[("active", COL_HEAD)], darkcolor=[("active", COL_HEAD)])

    # slim scrollbars without arrow buttons
    for orient, sticky in (("Vertical", "ns"), ("Horizontal", "ew")):
        style.layout(f"{orient}.TScrollbar", [(f"{orient}.Scrollbar.trough", {
            "sticky": sticky, "children": [
                (f"{orient}.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
        style.configure(f"{orient}.TScrollbar", background=COL_THUMB,
                        troughcolor=COL_PANEL, bordercolor=COL_PANEL,
                        lightcolor=COL_THUMB, darkcolor=COL_THUMB, gripcount=0,
                        arrowsize=px(10), relief="flat")
        style.map(f"{orient}.TScrollbar",
                  background=[("pressed", "#525a69"), ("active", "#474e5c")],
                  lightcolor=[("pressed", "#525a69"), ("active", "#474e5c")],
                  darkcolor=[("pressed", "#525a69"), ("active", "#474e5c")])

    # progress: a thin accent line
    for name in ("TProgressbar", "Horizontal.TProgressbar",
                 "Thin.Horizontal.TProgressbar"):
        style.configure(name, background=COL_ACCENT, troughcolor="#262b35",
                        bordercolor="#262b35", lightcolor=COL_ACCENT,
                        darkcolor=COL_ACCENT, thickness=px(4), borderwidth=0)

    # text entry
    for name, fg in (("TEntry", COL_FG), ("Placeholder.TEntry", COL_SUBTLE)):
        style.configure(name, fieldbackground=COL_FIELD, foreground=fg,
                        insertcolor=COL_FG, bordercolor=COL_FIELD,
                        lightcolor=COL_FIELD, darkcolor=COL_FIELD,
                        padding=(px(8), px(6)))
        style.map(name, bordercolor=[("focus", COL_ACCENT)],
                  lightcolor=[("focus", COL_FIELD)])
    style.configure("TCombobox", fieldbackground=COL_FIELD, background=COL_FIELD,
                    foreground=COL_FG, arrowcolor=COL_MUTED, bordercolor=COL_FIELD,
                    lightcolor=COL_FIELD, darkcolor=COL_FIELD,
                    padding=(px(8), px(5)))
    style.map("TCombobox", fieldbackground=[("readonly", COL_FIELD)],
              background=[("readonly", COL_FIELD), ("active", COL_BTN_HOVER)],
              foreground=[("readonly", COL_FG)],
              selectbackground=[("readonly", COL_FIELD)],
              selectforeground=[("readonly", COL_FG)],
              bordercolor=[("focus", COL_ACCENT)])
    root.option_add("*TCombobox*Listbox.background", COL_FIELD)
    root.option_add("*TCombobox*Listbox.foreground", COL_FG)
    root.option_add("*TCombobox*Listbox.selectBackground", COL_ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", COL_ON_ACCENT)
    root.option_add("*TCombobox*Listbox.font", f(10))
    style.configure("TSeparator", background=COL_LINE)


# --------------------------------------------------------------------------
# layout helpers
# --------------------------------------------------------------------------

def _card(parent: tk.Misc) -> tk.Frame:
    """A panel with a hairline border - the container for every table."""
    return tk.Frame(parent, bg=COL_PANEL, bd=0, highlightthickness=1,
                    highlightbackground=COL_LINE, highlightcolor=COL_LINE)


def _page_header(parent: tk.Misc, title: str, desc: str = "") -> ttk.Frame:
    """Title and one-line explanation; returns a frame on the right for actions."""
    head = ttk.Frame(parent)
    head.pack(fill="x", pady=(px(22), px(14)))
    actions = ttk.Frame(head)
    actions.pack(side="right", anchor="s")
    text = ttk.Frame(head)
    text.pack(side="left", fill="x", expand=True)
    ttk.Label(text, text=title, style="Title.TLabel").pack(anchor="w")
    if desc:
        lbl = ttk.Label(text, text=desc, style="Muted.TLabel", justify="left",
                        wraplength=px(560))
        lbl.pack(anchor="w", pady=(px(2), 0))
        # wrap to whatever width is left beside the action buttons
        text.bind("<Configure>", lambda e: lbl.configure(
            wraplength=max(px(240), min(e.width - px(8), px(820)))))
    return actions


def _placeholder(entry: ttk.Entry, text: str) -> None:
    """Grey hint text inside an empty entry, removed on focus."""
    entry._ph_active = False                       # type: ignore[attr-defined]

    def show(_e=None):
        if not entry.get():
            entry._ph_active = True                # type: ignore[attr-defined]
            entry.configure(style="Placeholder.TEntry")
            entry.insert(0, text)

    def hide(_e=None):
        if getattr(entry, "_ph_active", False):
            entry._ph_active = False               # type: ignore[attr-defined]
            entry.delete(0, "end")
            entry.configure(style="TEntry")

    entry.bind("<FocusIn>", hide, add="+")
    entry.bind("<FocusOut>", show, add="+")
    show()


def _entry_value(entry: ttk.Entry) -> str:
    return "" if getattr(entry, "_ph_active", False) else entry.get().strip()


def _set_entry(entry: ttk.Entry, value: str) -> None:
    if getattr(entry, "_ph_active", False):
        entry._ph_active = False                   # type: ignore[attr-defined]
        entry.configure(style="TEntry")
    entry.delete(0, "end")
    entry.insert(0, value)


class _Stack(ttk.Frame):
    """Shows one child page at a time.

    Mirrors the small part of the ttk.Notebook API the rest of the code (and the
    tests) rely on: select(index | widget | path), select() -> current path, and
    tabs()."""

    def __init__(self, master, on_change=None) -> None:
        super().__init__(master, style="TFrame")
        self._pages: list[tk.Widget] = []
        self._current: tk.Widget | None = None
        self.on_change = on_change

    def add(self, page: tk.Widget, text: str = "") -> None:
        self._pages.append(page)
        if self._current is None:
            self.select(page)

    def tabs(self) -> list[str]:
        return [str(p) for p in self._pages]

    def current(self) -> tk.Widget | None:
        return self._current

    def _resolve(self, target) -> tk.Widget:
        if isinstance(target, int):
            return self._pages[target]
        if isinstance(target, str):
            for p in self._pages:
                if str(p) == target:
                    return p
            raise tk.TclError(f"no page {target}")
        return target

    def select(self, target=None):
        if target is None:
            return str(self._current) if self._current is not None else ""
        page = self._resolve(target)
        if page is self._current:
            return None
        if self._current is not None:
            self._current.pack_forget()
        page.pack(fill="both", expand=True)
        self._current = page
        if self.on_change:
            self.on_change(page)
        return None


class _NavItem(tk.Frame):
    """One sidebar entry: accent bar, icon, label."""

    def __init__(self, master, text: str, icon: str, command) -> None:
        super().__init__(master, bg=COL_SIDE, cursor="hand2")
        self.command = command
        self.active = False
        self.bar = tk.Frame(self, bg=COL_SIDE, width=px(3))
        self.bar.pack(side="left", fill="y")
        self.icon = None
        if icon and ICON_FONT:
            self.icon = tk.Label(self, text=icon, font=(ICON_FONT, 11), bg=COL_SIDE,
                                 fg=COL_MUTED, width=2, cursor="hand2")
            self.icon.pack(side="left", padx=(px(13), 0))
        self.label = tk.Label(self, text=text, font=f(10), bg=COL_SIDE, fg=COL_MUTED,
                              anchor="w", cursor="hand2")
        self.label.pack(side="left", fill="x", expand=True,
                        padx=(px(8) if self.icon else px(19), px(10)), pady=px(6))
        for w in self._parts():
            w.bind("<Button-1>", lambda e: self.command())
            w.bind("<Enter>", lambda e: self._hover(True))
            w.bind("<Leave>", lambda e: self._hover(False))

    def _parts(self):
        return [w for w in (self, self.label, self.icon) if w is not None]

    def _paint(self, bg: str, fg: str, bar: str, icon_fg: str) -> None:
        for w in self._parts():
            w.configure(bg=bg)
        self.label.configure(fg=fg)
        if self.icon:
            self.icon.configure(fg=icon_fg)
        self.bar.configure(bg=bar)

    def set_active(self, on: bool) -> None:
        self.active = on
        if on:
            self._paint(COL_NAV_ACTIVE, COL_FG, COL_ACCENT, COL_ACCENT)
        else:
            self._paint(COL_SIDE, COL_MUTED, COL_SIDE, COL_MUTED)

    def _hover(self, inside: bool) -> None:
        if self.active:
            return
        if not inside:
            try:
                x, y = self.winfo_pointerxy()
                if self.winfo_containing(x, y) in self._parts():
                    return
            except (tk.TclError, KeyError):
                pass
        if inside:
            self._paint(COL_NAV_HOVER, COL_FG, COL_NAV_HOVER, COL_FG)
        else:
            self._paint(COL_SIDE, COL_MUTED, COL_SIDE, COL_MUTED)


class _Sidebar(tk.Frame):
    def __init__(self, master, app) -> None:
        super().__init__(master, bg=COL_SIDE, width=px(224))
        self.pack_propagate(False)
        self.app = app
        self.items: dict[str, _NavItem] = {}

        brand = tk.Frame(self, bg=COL_SIDE)
        brand.pack(fill="x", padx=px(18), pady=(px(16), px(10)))
        try:
            self._logo = tk.PhotoImage(master=self, file=ICON_SMALL_PNG)
            if S < 1.75:
                self._logo = self._logo.subsample(2, 2)
            tk.Label(brand, image=self._logo, bg=COL_SIDE).pack(side="left",
                                                               padx=(0, px(10)))
        except Exception:
            self._logo = None
        words = tk.Frame(brand, bg=COL_SIDE)
        words.pack(side="left")
        tk.Label(words, text="Sweep", font=f(15, True), bg=COL_SIDE, fg=COL_FG).pack(anchor="w")
        tk.Label(words, text=f"version {__version__}", font=f(8), bg=COL_SIDE,
                 fg=COL_SUBTLE).pack(anchor="w")

        self.bottom = tk.Frame(self, bg=COL_SIDE)
        self.bottom.pack(side="bottom", fill="x", pady=(0, px(12)))
        self.nav = tk.Frame(self, bg=COL_SIDE)
        self.nav.pack(fill="x")

    def heading(self, text: str) -> None:
        tk.Label(self.nav, text=text.upper(), font=f(8, True), bg=COL_SIDE,
                 fg=COL_SUBTLE, anchor="w").pack(fill="x", padx=px(22),
                                                 pady=(px(14), px(4)))

    def item(self, key: str, text: str, command, parent=None) -> _NavItem:
        it = _NavItem(parent or self.nav, text, ICONS.get(key, ""), command)
        it.pack(fill="x")
        self.items[key] = it
        return it

    def set_active(self, key: str) -> None:
        for k, it in self.items.items():
            if k != "settings":
                it.set_active(k == key)


# --------------------------------------------------------------------------
# reusable tables
# --------------------------------------------------------------------------

class _Table(ttk.Frame):
    """A Treeview with striping, scrollbars that appear only when needed, and an
    optional empty-state hint.

    Columns widen to fit what is put in them, up to CAP pixels; the table then
    scrolls sideways rather than hiding data. Anything wider than CAP is
    shortened with an ellipsis, and hovering it shows the full text."""

    CAP = 760

    def __init__(self, master, columns, tree_heading="Name",
                 tree_width=px(300), selectmode="browse", empty_text: str = "",
                 caps: dict | None = None):
        super().__init__(master, style="Card.TFrame")
        self.columns = columns
        self.caps = dict(caps or {})          # per-column limit on auto-widening
        self.tree = ttk.Treeview(self, columns=[c[0] for c in columns],
                                 show="tree headings", selectmode=selectmode)
        # Only the last text column stretches to fill spare width, and no column
        # may shrink below what it already holds: a narrow window scrolls
        # sideways instead of squeezing columns down to stubs.
        text_cols = [c[0] for c in columns if c[3] != "e"]
        self._stretch_col = text_cols[-1] if text_cols else "#0"
        self.tree.heading("#0", text=tree_heading, anchor="w")
        self.tree.column("#0", width=tree_width, minwidth=tree_width, anchor="w",
                         stretch=(self._stretch_col == "#0"))
        self._widths = {"#0": tree_width}
        for key, heading, width, anchor in columns:
            self.tree.heading(key, text=heading, anchor=anchor)
            self.tree.column(key, width=width, minwidth=width, anchor=anchor,
                             stretch=(key == self._stretch_col))
            self._widths[key] = width
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.hsb = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=lambda a, b: self._scrolled(self.vsb, a, b),
                            xscrollcommand=lambda a, b: self._scrolled(self.hsb, a, b))
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.vsb.grid(row=0, column=1, sticky="ns")
        self.hsb.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        _stripe(self.tree)
        self.tree.tag_configure("muted", foreground=COL_MUTED)
        self.tree.tag_configure("ok", foreground=COL_GREEN)
        self.tree.tag_configure("warn", foreground=COL_AMBER)
        self.tree.tag_configure("bad", foreground=COL_RED)
        self._n = 0
        self._font = tkfont.Font(root=self, font=f(10))
        self._full: dict[tuple[str, str], str] = {}
        self._tip: tk.Toplevel | None = None
        self._tip_lbl: tk.Label | None = None
        self._tip_key = None
        self.tree.bind("<Motion>", self._hover, add="+")
        self.tree.bind("<Leave>", lambda e: self._hide_tip(), add="+")
        self._empty_text = empty_text
        self.empty = tk.Label(self, text=empty_text, bg=COL_PANEL, fg=COL_SUBTLE,
                              font=f(10), justify="center")
        self._show_empty()

    # ---- scrollbars ---------------------------------------------------------
    def _scrolled(self, bar: ttk.Scrollbar, first, last) -> None:
        self._hide_tip()          # the cell under a tooltip moves when the view scrolls
        self._autohide(bar, first, last)

    @staticmethod
    def _autohide(bar: ttk.Scrollbar, first, last) -> None:
        first, last = float(first), float(last)
        if first <= 0.0 and last >= 1.0:
            bar.grid_remove()
        else:
            bar.grid()
        bar.set(first, last)

    # ---- empty state --------------------------------------------------------
    def _show_empty(self) -> None:
        if self._empty_text and not self.tree.get_children():
            width = self.tree.winfo_width()
            self.empty.configure(text=self._empty_text,
                                 wraplength=max(px(260), width - px(80)) if width > 1
                                 else px(520))
            self.empty.place(in_=self.tree, relx=0.5, rely=0.5, anchor="center")
        else:
            self.empty.place_forget()

    def set_empty(self, text: str) -> None:
        self._empty_text = text
        self._show_empty()

    # ---- fitting text to columns -------------------------------------------
    def _ellipsize(self, text: str, avail: int) -> str:
        if self._font.measure(text) <= avail:
            return text
        lo, hi = 0, len(text)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._font.measure(text[:mid] + "\u2026") <= avail:
                lo = mid
            else:
                hi = mid - 1
        return text[:lo].rstrip() + "\u2026"

    def _fit(self, iid: str, col: str, value, extra: int = 0) -> str:
        """Widen the column to fit `value` (up to CAP); beyond that, shorten it
        with an ellipsis and remember the full text for the hover tooltip."""
        self._full.pop((iid, col), None)
        text = "" if value is None else str(value)
        if not text:
            return text
        pad = px(20) + extra
        need = self._font.measure(text) + pad
        cap = self.caps.get(col, px(self.CAP))
        try:
            fit = min(need, cap)
            if fit > int(self.tree.column(col, "minwidth")):
                width = max(fit, int(self.tree.column(col, "width")))
                self.tree.column(col, minwidth=fit, width=width)
        except tk.TclError:
            return text
        if need > cap:
            self._full[(iid, col)] = text
            return self._ellipsize(text, cap - pad)
        return text

    def _fill(self, iid: str, label: str, values, has_image: bool) -> None:
        text = self._fit(iid, "#0", label, px(20) + (px(19) if has_image else 0))
        vals = [self._fit(iid, c[0], v) for c, v in zip(self.columns, values)]
        self.tree.item(iid, text=f" {text}" if has_image else text, values=vals)

    # ---- hover tooltip with the full text ------------------------------------
    def _hover(self, e) -> None:
        iid = self.tree.identify_row(e.y)
        colid = self.tree.identify_column(e.x)
        key = None
        if iid and colid:
            if colid == "#0":
                key = "#0"
            else:
                try:
                    key = self.tree["columns"][int(colid[1:]) - 1]
                except (ValueError, IndexError):
                    key = None
        text = self._full.get((iid, key)) if key else None
        if not text:
            self._hide_tip()
            return
        if self._tip is None:
            self._tip = tk.Toplevel(self)
            self._tip.withdraw()
            self._tip.overrideredirect(True)
            try:
                self._tip.attributes("-topmost", True)
            except tk.TclError:
                pass
            self._tip_lbl = tk.Label(self._tip, bg=COL_TIP, fg=COL_FG, font=f(9),
                                     justify="left", wraplength=px(640), padx=px(9),
                                     pady=px(6), highlightthickness=1,
                                     highlightbackground=COL_LINE)
            self._tip_lbl.pack()
        if self._tip_key != (iid, key):
            self._tip_lbl.configure(text=text)
            self._tip_key = (iid, key)
        self._tip.geometry(f"+{e.x_root + px(14)}+{e.y_root + px(18)}")
        self._tip.deiconify()

    def _hide_tip(self) -> None:
        if self._tip is not None:
            self._tip.withdraw()
        self._tip_key = None

    # ---- rows ---------------------------------------------------------------
    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._n = 0
        self._full.clear()
        self._hide_tip()
        for col, width in self._widths.items():
            try:
                self.tree.column(col, width=width, minwidth=width)
            except tk.TclError:
                pass
        self._show_empty()

    def add(self, label: str, values, tag: str | None = None,
            image: tk.PhotoImage | None = None, iid: str | None = None) -> str:
        tags = ["odd" if self._n % 2 else "even"]
        if tag:
            tags.append(tag)
        kw = {"text": "", "values": tuple(values), "tags": tuple(tags)}
        if image is not None:
            kw["image"] = image
        if iid is not None:
            kw["iid"] = iid
        iid = self.tree.insert("", "end", **kw)
        self._fill(iid, label, values, image is not None)
        self._n += 1
        self.empty.place_forget()
        return iid

    def set(self, iid: str, column: str, value) -> None:
        try:
            self.tree.set(iid, column, self._fit(iid, column, value))
        except tk.TclError:
            pass

    def selected(self) -> list[str]:
        return list(self.tree.selection())

    def rows(self) -> list[str]:
        return list(self.tree.get_children())


class _CheckList(_Table):
    """A table with a checkbox per row, toggled by clicking anywhere on the row."""

    def __init__(self, master, columns, tree_heading="Item",
                 tree_width=px(420), on_change=None, on_row_click=None,
                 empty_text: str = ""):
        super().__init__(master, columns, tree_heading=tree_heading,
                         tree_width=tree_width, selectmode="none",
                         empty_text=empty_text)
        self.on_change = on_change
        self.on_row_click = on_row_click
        self.rows_meta: dict[str, dict] = {}
        self.tree.bind("<Button-1>", self._on_click)

    def clear(self) -> None:
        self.rows_meta.clear()
        super().clear()

    def _box(self, checked: bool) -> tk.PhotoImage:
        return _img(self, "box:on" if checked else "box:off")

    def add(self, key, label, values, checked=True, tag=None, payload=None) -> str:
        tags = ["odd" if self._n % 2 else "even"]
        if tag:
            tags.append(tag)
        iid = self.tree.insert("", "end", text="", image=self._box(checked),
                               values=tuple(values), tags=tuple(tags))
        self._fill(iid, label, values, True)
        self._n += 1
        self.empty.place_forget()
        self.rows_meta[iid] = {"key": key, "label": label, "checked": checked,
                               "tag": tag, "payload": payload, "stripe": tags[0]}
        self._notify()
        return iid

    def _on_click(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if iid and iid in self.rows_meta:
            self.toggle(iid)
            if self.on_row_click:
                self.on_row_click(self.rows_meta[iid])

    def toggle(self, iid: str) -> None:
        meta = self.rows_meta.get(iid)
        if not meta:
            return
        self.set_checked(iid, not meta["checked"], notify=True)

    def set_checked(self, iid: str, checked: bool, notify: bool = False) -> None:
        meta = self.rows_meta.get(iid)
        if not meta:
            return
        meta["checked"] = checked
        self.tree.item(iid, image=self._box(checked))
        if notify:
            self._notify()

    def set_all(self, checked: bool) -> None:
        for iid in self.rows_meta:
            self.set_checked(iid, checked)
        self._notify()

    def checked(self) -> list[dict]:
        return [m for m in self.rows_meta.values() if m["checked"]]

    def mark(self, iid: str, column: str, text: str, tag: str | None = None,
             message: str | None = None) -> None:
        meta = self.rows_meta.get(iid)
        if not meta:
            return
        self.set(iid, column, text)
        if message is not None:
            meta["message"] = message
        tags = [meta["stripe"]]
        if tag:
            tags.append(tag)
            meta["tag"] = tag
        try:
            self.tree.item(iid, tags=tuple(tags))
        except tk.TclError:
            pass

    def _notify(self) -> None:
        if self.on_change:
            self.on_change(self.checked())


def _join(names: list[str]) -> str:
    """'A', 'A and B', 'A, B and C'."""
    names = [n for n in names if n]
    if len(names) <= 1:
        return "".join(names)
    return ", ".join(names[:-1]) + " and " + names[-1]


def _needs_admin(reason: str) -> bool:
    low = (reason or "").lower()
    return ("administrator" in low or "admin" in low or "elevat" in low
            or ("access" in low and "denied" in low))


def update_empty_message(total: int, notes: list[str], checked: list[str] | None = None,
                         missed: list[str] | None = None) -> str:
    """What the empty Updates list should say ("" = show no empty state).

    A pure function so the wording can be tested without a display. The rule it
    encodes: "nothing found" and "could not look" are different answers, and
    only the first one means you are up to date. `checked` / `missed` name the
    sources that were and were not reached, when the caller knows them.
    """
    if total:
        return ""
    if not notes:
        if checked:
            verb = "has" if len(checked) == 1 else "have"
            return f"Up to date: {_join(checked)} {verb} nothing to install."
        return "Everything Sweep can see is up to date"
    who = _join(missed) if missed else "Some sources"
    if checked:
        return (f"{_join(checked)}: nothing to install.\n"
                f"{who} could not be checked - see the note above.")
    return (f"{who} could not be checked, so Sweep cannot tell whether updates "
            "are waiting.\nSee the note above.")


def update_summary(total: int, notes: list[str], missed: list[str] | None = None) -> str:
    """The one-line status under the Updates list."""
    lead = f"could not check {_join(missed)}" if missed else "could not check"
    if total:
        text = f"{total} update(s) available"
        if notes:
            text += f"   \u00b7   {lead}: {_short_note(notes[0])}"
        return text
    if notes:
        extra = f"  (+{len(notes) - 1} more)" if len(notes) > 1 else ""
        return f"{lead}: {_short_note(notes[0])}{extra}"
    return "everything visible to Sweep is current"


def _short_note(note: str, limit: int = 90) -> str:
    """First clause of a failure message, so a status line stays one line. Cuts
    on a clause or word boundary, never mid-token - a truncated error code such
    as "(0x8A" is worse than none."""
    text = (note or "").strip()
    for sep in (". ", " - ", "; "):
        idx = text.find(sep)
        if 0 < idx <= limit:
            return text[:idx]
    if len(text) <= limit:
        return text
    cut = text.rfind(" ", 0, limit)
    head = text[:cut] if cut > 40 else text[:limit]
    return head.rstrip(" ,;:-") + "\u2026"


class _Notice(tk.Frame):
    """An amber strip for what must not be missed - a check that could not run,
    or a step that needs administrator rights - with an optional action."""

    def __init__(self, master) -> None:
        super().__init__(master, bg=COL_WARN_BG)
        tk.Label(self, image=_img(self, f"dot:{COL_AMBER}"), bg=COL_WARN_BG).pack(
            side="left", anchor="n", padx=(px(12), px(8)), pady=px(10))
        self.btn = ttk.Button(self, text="")
        self.msg = tk.Label(self, bg=COL_WARN_BG, fg=COL_FG, font=f(10),
                            justify="left", anchor="w")
        self.msg.pack(side="left", fill="x", expand=True, pady=px(9))
        self.bind("<Configure>", lambda e: self._rewrap())

    def _rewrap(self) -> None:
        used = px(46) + (self.btn.winfo_reqwidth() + px(20)
                         if self.btn.winfo_manager() else 0)
        self.msg.configure(wraplength=max(px(220), self.winfo_width() - used))

    def show(self, text: str, action=None, **pack) -> None:
        """action = (button label, command) or None; pack = where to place it."""
        self.msg.configure(text=text)
        if action:
            label, command = action
            self.btn.configure(text=label, command=command)
            if not self.btn.winfo_manager():
                self.btn.pack(side="right", anchor="center", padx=px(10), pady=px(6),
                              before=self.msg)
        else:
            self.btn.pack_forget()
        if not self.winfo_manager():
            self.pack(**pack)
        self.after_idle(self._rewrap)

    def hide(self) -> None:
        self.pack_forget()


def _autowrap(label: tk.Widget, container: tk.Widget, minus: int = 0) -> None:
    """Wrap a status line to its container instead of letting it run off the edge."""
    container.bind("<Configure>", lambda e: label.configure(
        wraplength=max(px(200), e.width - minus)), add="+")


# --------------------------------------------------------------------------
# Clean page
# --------------------------------------------------------------------------

IMPORTED_GROUP = "CCleaner rules (imported)"


class CleanTab(ttk.Frame):
    TITLE = "Clean"
    DESC = ("Find junk that is safe to remove. Scanning only measures - nothing is "
            "deleted until you press Clean and confirm.")

    def __init__(self, master, app) -> None:
        super().__init__(master, style="TFrame")
        self.app = app
        self.worker = Worker(self)
        self.selected: set[str] = {r["id"] for r in rules.defaults()}
        self.last_scan: scanner.ScanResult | None = None
        self.rows: dict[str, str] = {}          # tree item -> rule id
        self.group_items: dict[str, str] = {}   # group label -> tree item
        self.group_meta: dict[str, list[str]] = {}   # tree item -> rule ids under it
        self._group_keys: dict[str, str] = {}
        self._open: dict[str, bool] = {}
        self._stripes: dict[str, str] = {}
        self._risk: dict[str, str] = {}
        self._admin = base.is_admin()
        self.only_found = tk.BooleanVar(value=False)
        self._build()

    def _build(self) -> None:
        _page_header(self, self.TITLE, self.DESC)

        # summary card: the number that matters, and the two actions
        hero = _card(self)
        hero.pack(fill="x")
        inner = tk.Frame(hero, bg=COL_PANEL)
        inner.pack(fill="x", padx=px(22), pady=px(18))
        right = tk.Frame(inner, bg=COL_PANEL)
        right.pack(side="right", anchor="n")
        btns = tk.Frame(right, bg=COL_PANEL)
        btns.pack(anchor="e")
        self.cancel_btn = ttk.Button(btns, text="Stop", command=self.do_cancel,
                                     state="disabled")
        self.clean_btn = ttk.Button(btns, text="Clean selected", command=self.do_clean,
                                    state="disabled")
        self.clean_btn.pack(side="left", padx=(0, px(8)))
        self.scan_btn = ttk.Button(btns, text="Scan", style="Accent.TButton",
                                   command=self.do_scan, width=10)
        self.scan_btn.pack(side="left")
        ttk.Checkbutton(right, text="Send to Recycle Bin (can be undone)",
                        variable=self.app.recycle_var, style="Card.TCheckbutton",
                        command=self.app._toggle_recycle).pack(anchor="e", pady=(px(12), 0))

        left = tk.Frame(inner, bg=COL_PANEL)
        left.pack(side="left", fill="x", expand=True)
        self.total_lbl = ttk.Label(left, text="Not scanned yet", style="Hero.TLabel")
        self.total_lbl.pack(anchor="w")
        self.status = ttk.Label(left, text="Choose categories below, then press Scan.",
                                style="CardMuted.TLabel", justify="left")
        self.status.pack(anchor="w", fill="x", pady=(px(2), 0))
        _autowrap(self.status, left, minus=px(4))
        self.progress = ttk.Progressbar(hero, mode="determinate",
                                        style="Thin.Horizontal.TProgressbar")

        # selection toolbar
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(px(16), px(8)))
        ttk.Label(bar, text="Select", style="Muted.TLabel").pack(side="left", padx=(0, px(4)))
        for text, cmd in (("Recommended", self.sel_defaults), ("All", self.sel_all),
                          ("None", self.sel_none)):
            ttk.Button(bar, text=text, style="Link.TButton", command=cmd).pack(side="left")
        self.found_chk = ttk.Checkbutton(bar, text="Only show what was found",
                                         variable=self.only_found, state="disabled",
                                         command=self._populate)
        self.found_chk.pack(side="left", padx=(px(20), 0))
        ttk.Button(bar, text="Import CCleaner rules\u2026",
                   command=self.import_ccleaner).pack(side="right")
        legend = ttk.Frame(bar)
        legend.pack(side="right", padx=(0, px(20)))
        for risk in ("safe", "moderate", "caution"):
            tk.Label(legend, image=_img(self, f"dot:{RISK_COLOR[risk]}"),
                     bg=COL_BG).pack(side="left")
            ttk.Label(legend, text=risk, style="Muted.TLabel").pack(
                side="left", padx=(px(3), px(12)))

        # on a narrow window the legend gives way rather than overlapping
        def fit_legend(e, legend=legend):
            want = e.width >= px(900)
            if want and not legend.winfo_ismapped():
                legend.pack(side="right", padx=(0, px(20)))
            elif not want and legend.winfo_ismapped():
                legend.pack_forget()
        bar.bind("<Configure>", fit_legend)

        card = _card(self)
        card.pack(fill="both", expand=True)
        self.table = _Table(card, [
            ("size", "Size", px(110), "e"),
            ("files", "Files", px(100), "e"),
            ("note", "Notes", px(170), "w"),
        ], tree_heading="Category", tree_width=px(330), selectmode="none",
            caps={"#0": px(470)})
        self.table.pack(fill="both", expand=True)
        self.tree = self.table.tree
        self.tree.tag_configure("group", font=f(10, True), foreground=COL_FG)
        self.tree.tag_configure("off", foreground=COL_MUTED)
        self.tree.bind("<Button-1>", self._on_click)
        self._populate()

    # ---- tree ----------------------------------------------------------

    def _tri(self, ids: list[str]) -> str:
        k = sum(1 for i in ids if i in self.selected)
        if k == 0:
            return "off"
        return "on" if k == len(ids) else "mixed"

    def _rule_values(self, r: dict, rr) -> tuple[str, str, str]:
        notes = []
        if r.get("needs_admin") and not self._admin:
            notes.append("needs admin")
        if rr is None:
            return ("", "", ", ".join(notes))
        # Report denial and error BEFORE the empty test. An all-denied rule has
        # a count of zero but is not empty - it was never measured. Returning
        # early here used to hide exactly the case that matters.
        if rr.error:
            notes.append("error")
        elif rr.denied:
            notes.append(f"{rr.denied:,} denied")
        if rr.empty:
            return ("\u2013", "", ", ".join(notes))
        size_txt = base.human(rr.size) if rr.size else "\u2013"
        files_txt = f"{rr.count:,}"
        if rr.reg_items and not rr.files:
            files_txt = f"{rr.count:,} reg"
        elif rr.reg_items:
            notes.append(f"{len(rr.reg_items)} registry")
        return (size_txt, files_txt, ", ".join(notes))

    def _populate(self) -> None:
        # remember which groups were open so a refresh does not reset the view
        for gid, key in self._group_keys.items():
            try:
                self._open[key] = bool(self.tree.item(gid, "open"))
            except tk.TclError:
                pass
        self.table.clear()
        for d in (self.rows, self.group_items, self.group_meta, self._group_keys,
                  self._stripes):
            d.clear()
        self._risk = {r["id"]: r.get("risk", "safe") for r in rules.RULES}

        res = self.last_scan
        by_id = {r.rule_id: r for r in res.results} if res else {}
        only = bool(self.only_found.get()) and res is not None
        totals = scanner.group_totals(res) if res else {}
        counter = [0]

        def visible(r: dict) -> bool:
            if not only:
                return True
            rr = by_id.get(r["id"])
            if rr is None:
                return False
            # "found" must not hide a rule that could not be read: that is the
            # difference between an empty folder and an unreadable one.
            return not rr.empty or bool(rr.denied) or bool(rr.error)

        def rollup(b: int, c: int) -> tuple[str, str, str]:
            if res is None:
                return ("", "", "")
            return (base.human(b) if b else "\u2013", f"{c:,}" if c else "", "")

        def add_group(parent: str, key: str, label: str, rs: list[dict],
                      default_open: bool) -> None:
            shown = [r for r in rs if visible(r)]
            if only and not shown:
                return
            ids = [r["id"] for r in rs]
            b, c = totals.get(label, (0, 0))
            gid = self.tree.insert(parent, "end", text=f" {label}",
                                   image=_img(self, "box:" + self._tri(ids)),
                                   values=rollup(b, c),
                                   open=self._open.get(key, default_open),
                                   tags=("group",))
            self.group_items[label] = gid
            self.group_meta[gid] = ids
            self._group_keys[gid] = key
            for r in shown:
                on = r["id"] in self.selected
                stripe = "odd" if counter[0] % 2 else "even"
                counter[0] += 1
                iid = self.tree.insert(
                    gid, "end", text=f" {r['name']}",
                    image=_img(self, f"boxdot:{'on' if on else 'off'}:{r.get('risk', 'safe')}"),
                    values=self._rule_values(r, by_id.get(r["id"])),
                    tags=(stripe, "on" if on else "off"))
                depth = 2 if parent else 1
                shown_name = self.table._fit(iid, "#0", r["name"],
                                             px(20) * depth + px(40))
                if shown_name != r["name"]:
                    self.tree.item(iid, text=f" {shown_name}")
                self.rows[iid] = r["id"]
                self._stripes[iid] = stripe

        builtin, imported = [], []
        for group, rs in rules.by_group().items():
            (imported if all(r.get("imported") for r in rs) else builtin).append((group, rs))
        for group, rs in builtin:
            add_group("", "g:" + group, group, rs, default_open=True)

        if imported:
            all_ids = [r["id"] for _g, rs in imported for r in rs]
            if not only or any(visible(r) for _g, rs in imported for r in rs):
                b = sum(totals.get(g, (0, 0))[0] for g, _rs in imported)
                c = sum(totals.get(g, (0, 0))[1] for g, _rs in imported)
                pid = self.tree.insert("", "end", text=f" {IMPORTED_GROUP}",
                                       image=_img(self, "box:" + self._tri(all_ids)),
                                       values=rollup(b, c),
                                       open=self._open.get("imported", only),
                                       tags=("group",))
                self.group_items[IMPORTED_GROUP] = pid
                self.group_meta[pid] = all_ids
                self._group_keys[pid] = "imported"
                for group, rs in imported:
                    add_group(pid, "i:" + group, group, rs, default_open=False)
        self._update_clean_state()

    def _refresh_marks(self) -> None:
        for iid, rid in self.rows.items():
            on = rid in self.selected
            self.tree.item(iid, image=_img(
                self, f"boxdot:{'on' if on else 'off'}:{self._risk.get(rid, 'safe')}"),
                tags=(self._stripes.get(iid, "even"), "on" if on else "off"))
        for gid, ids in self.group_meta.items():
            self.tree.item(gid, image=_img(self, "box:" + self._tri(ids)))
        self._update_clean_state()

    def _on_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return None
        if "indicator" in str(self.tree.identify_element(event.x, event.y)):
            return None                         # let Tk open/close the group
        if self.tree.identify_region(event.x, event.y) not in ("tree", "cell"):
            return None
        if iid in self.rows:
            rid = self.rows[iid]
            if rid in self.selected:
                self.selected.discard(rid)
            else:
                self.selected.add(rid)
        elif iid in self.group_meta:
            ids = self.group_meta[iid]
            # ticking a whole group never switches on caution-level rules;
            # those stay a deliberate, one-at-a-time choice
            pick = [i for i in ids if self._risk.get(i) != "caution"] or ids
            if all(i in self.selected for i in pick):
                self.selected.difference_update(ids)
            else:
                self.selected.update(pick)
        else:
            return None
        self._refresh_marks()
        return "break"

    def _update_clean_state(self) -> None:
        ready = self.last_scan is not None and bool(self.selected)
        if self.worker.busy:
            return
        self.clean_btn.configure(state="normal" if ready else "disabled",
                                 style="Accent.TButton" if ready else "TButton")
        self.scan_btn.configure(style="TButton" if ready else "Accent.TButton")

    def _set_running(self, running: bool) -> None:
        if running:
            self.cancel_btn.configure(state="normal")
            self.cancel_btn.pack(side="left", padx=(0, px(8)), before=self.clean_btn)
            self.progress.pack(side="bottom", fill="x")
            self.scan_btn.configure(state="disabled")
            self.clean_btn.configure(state="disabled")
        else:
            self.cancel_btn.configure(state="disabled")
            self.cancel_btn.pack_forget()
            self.progress.pack_forget()
            self.progress.configure(value=0)
            self.scan_btn.configure(state="normal")
            self._update_clean_state()

    # ---- selection buttons ---------------------------------------------

    def sel_defaults(self) -> None:
        self.selected = {r["id"] for r in rules.defaults()}
        self._refresh_marks()

    def sel_all(self) -> None:
        self.selected = set(rules.ids())
        self._refresh_marks()

    def sel_none(self) -> None:
        self.selected.clear()
        self._refresh_marks()

    # ---- import CCleaner rules -----------------------------------------

    def import_ccleaner(self) -> None:
        from . import ccimport
        found = ccimport.find_installations()
        if not found:
            messagebox.showinfo(
                "Sweep",
                "No CCleaner ruleset was found on this machine.\n\n"
                "Sweep reads ccleaner.ini from an existing installation; "
                "nothing is downloaded.")
            return
        if not messagebox.askyesno(
                "Import CCleaner rules",
                f"Read the ruleset from:\n{found[0]}\n\n"
                "Its categories are added as extra rules, off by default, and "
                "still run through Sweep's safety checks.\n\nContinue?"):
            return
        try:
            rep = ccimport.parse(found[0])
            out = ccimport.default_output()
            ccimport.save(rep, out)
            rules.unload_external()
            rules.load_external(out)
        except Exception as exc:                    # noqa: BLE001
            messagebox.showerror("Import failed", str(exc))
            return
        self.selected = {r["id"] for r in rules.defaults()}
        self.last_scan = None
        self.only_found.set(False)
        self.found_chk.configure(state="disabled")
        self.total_lbl.configure(text="Not scanned yet")
        self.status.configure(text="Imported rules are listed at the bottom, off by default.")
        self._populate()
        self.app.refresh_facts()
        messagebox.showinfo("Import complete",
                            rep.summary() + "\n\nReview them before selecting.")

    # ---- actions -------------------------------------------------------

    def do_cancel(self) -> None:
        self.worker.cancel.set()
        self.status.configure(text="Stopping\u2026")

    def do_scan(self) -> None:
        if self.worker.busy:
            return
        ids = sorted(self.selected)
        if not ids:
            messagebox.showinfo("Sweep", "Select at least one category to scan.")
            return
        self._set_running(True)
        self.progress.configure(maximum=len(ids), value=0)
        self.status.configure(text=f"Measuring {len(ids)} categories\u2026")
        self.app.set_status("scanning for junk\u2026", source=self)
        self.total_lbl.configure(text="Scanning\u2026")

        def job(cancel, emit):
            return scanner.scan(ids, cancel=cancel,
                                progress=lambda d, t, lbl, sz: emit(d, t, lbl, sz))

        def progress(done, total, label, size):
            self.progress.configure(value=done)
            self.status.configure(text=f"{label}   \u00b7   {base.human(size)}")

        def done(res: scanner.ScanResult):
            self.last_scan = res
            self._set_running(False)
            found = len(res.actionable())
            unclear = sum(r.denied for r in res.results)
            if not res.total_size and unclear:
                # "0 B" would read as a clean machine. It is not: nothing was
                # measured. Say so instead.
                self.total_lbl.configure(
                    text="Nothing could be measured \u2014 some paths are unreadable")
            else:
                self.total_lbl.configure(text=f"{base.human(res.total_size)} can be freed")
            status = (f"{res.total_count:,} files in {found} categor"
                      f"{'y' if found == 1 else 'ies'}   \u00b7   scanned in {res.duration:.1f}s")
            if unclear:
                status += f"   \u00b7   {unclear:,} path(s) not readable"
            self.status.configure(text=status)
            self.only_found.set(True)
            self.found_chk.configure(state="normal")
            self._populate()
            self.app.set_status(f"found {base.human(res.total_size)} in {res.total_count:,} files", source=self)

        def error(exc, tb):
            self._set_running(False)
            self.total_lbl.configure(text="Scan failed")
            self.status.configure(text=str(exc)[:120])
            messagebox.showerror("Scan failed", f"{exc}\n\n{tb[-800:]}")

        self.worker.start(job, progress, done, error)

    def _apply_results(self, res: scanner.ScanResult) -> None:
        self.last_scan = res
        self._populate()

    def do_clean(self) -> None:
        if self.worker.busy or self.last_scan is None:
            return
        res = self.last_scan
        ids = [r for r in self.selected]
        plan = [r for r in res.results if r.rule_id in ids and not r.empty]
        if not plan:
            in_selection = [r for r in res.results if r.rule_id in ids]
            denied = sum(r.denied for r in in_selection)
            errored = sum(1 for r in in_selection if r.error)
            if denied or errored:
                msg = f"{denied:,} path(s) were denied by Windows"
                if errored:
                    msg += f" and {errored} rule(s) could not run"
                messagebox.showwarning(
                    "Sweep",
                    f"Nothing could be measured for this selection.\n\n{msg}."
                    "\n\nRestart Sweep as administrator to measure them, then try "
                    "again - these items were never checked, not found clean.",
                    parent=self)
            else:
                messagebox.showinfo("Sweep", "Nothing selected has anything to clean.",
                                    parent=self)
            return

        total = sum(r.size for r in plan)
        caution = [r for r in plan if r.risk == "caution"]
        actions = [r for r in plan if r.action]
        msg = [f"Free {base.human(total)} across {sum(r.count for r in plan):,} files?"]
        if actions:
            msg.append("\nThis also runs system actions: " +
                       ", ".join(a.name for a in actions))
        if caution:
            msg.append("\n\nIncludes caution-level rules:\n  " +
                       "\n  ".join(c.name for c in caution))
        if self.app.recycle_var.get():
            msg.append("\n\nFiles go to the Recycle Bin, so this can be undone.")
        msg.append("\n\nFiles in use are skipped. An audit log is written to\n"
                   "%LOCALAPPDATA%\\Sweep\\logs\\")
        if not messagebox.askyesno("Confirm clean", "".join(msg), icon="warning"):
            return

        self._set_running(True)
        self.total_lbl.configure(text="Cleaning\u2026")
        self.status.configure(text="Removing files\u2026")
        self.progress.configure(maximum=len(plan), value=0)

        log_path = os.path.join(
            base.state_dir(), "logs", f"clean-{time.strftime('%Y%m%d-%H%M%S')}.jsonl")
        mode = "recycle" if self.app.recycle_var.get() else "delete"
        log = cleaner.SessionLog(log_path)

        def job(cancel, emit):
            try:
                return cleaner.clean(res, rule_ids=ids, confirm=True, mode=mode,
                                     log=log, cancel=cancel,
                                     progress=lambda d, t, lbl, b: emit(d, t, lbl, b))
            finally:
                log.close()

        def progress(done, total_, label, size):
            self.progress.configure(value=done)
            self.status.configure(text=f"{label}   \u00b7   {base.human(size)}")

        def done(rep: cleaner.CleanReport):
            self.last_scan = None
            self._set_running(False)
            self.total_lbl.configure(text=f"{base.human(rep.bytes)} freed")
            self.status.configure(text=f"{rep.deleted:,} files removed   \u00b7   "
                                       "audit log saved")
            self.app.set_status(f"freed {base.human(rep.bytes)} ({rep.deleted:,} files)", source=self)
            self.only_found.set(False)
            self.found_chk.configure(state="disabled")
            self._populate()
            extra = ""
            if rep.locked:
                extra += (f"\n\n{rep.locked:,} file(s) were in use and skipped."
                          "\nClose the owning application and scan again.")
            if rep.denied:
                extra += (f"\n\n{rep.denied:,} file(s) were denied by Windows."
                          "\nRestart Sweep as administrator to clean those.")
            if rep.failed:
                extra += f"\n\n{rep.failed:,} file(s) failed for other reasons."
            if rep.restore_point:
                extra += f"\n\nRestore point: {rep.restore_point}"
            action_errors = [o.action_result for o in rep.outcomes
                             if o.action_result and str(o.action_result).startswith("error")]
            if action_errors:
                extra += ("\n\nSystem actions that failed:\n"
                          + "\n".join(f"  {e}" for e in action_errors[:5]))
            messagebox.showinfo(
                "Clean complete",
                f"Freed {base.human(rep.bytes)} ({rep.deleted:,} files).{extra}\n\n"
                f"Audit log:\n{rep.log_path}")

        def error(exc, tb):
            self._set_running(False)
            self.total_lbl.configure(text="Clean failed")
            self.status.configure(text=str(exc)[:120])
            messagebox.showerror("Clean failed", f"{exc}\n\n{tb[-800:]}")

        self.worker.start(job, progress, done, error)


# --------------------------------------------------------------------------
# Space page
# --------------------------------------------------------------------------

PALETTE = ["#3b7dd8", "#35996a", "#bf8a2d", "#8a60b8", "#2b93a5",
           "#bd5258", "#5c76a3", "#5a9b4c", "#a77843", "#7666b3"]


class SpaceTab(ttk.Frame):
    TITLE = "Space"
    DESC = "See what is filling the disk. Click a block to look inside it."

    def __init__(self, master, app) -> None:
        super().__init__(master, style="TFrame")
        self.app = app
        self.worker = Worker(self)
        self.root_node: analyzer.Node | None = None
        self.view_node: analyzer.Node | None = None
        self.rects: list[tuple[str, float, float, float, float, str]] = []
        self._file_paths: dict[str, str] = {}
        self._build()

    def _build(self) -> None:
        _page_header(self, self.TITLE, self.DESC)

        # packed right-to-left so the path entry takes whatever width is left
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, px(10)))
        self.path = tk.StringVar(value="C:\\")
        self.dupes = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Find duplicates (slower)",
                        variable=self.dupes).pack(side="right", padx=(px(16), 0))
        self.up_btn = ttk.Button(bar, text="\u2191 Up", command=self.go_up, state="disabled")
        self.up_btn.pack(side="right", padx=(px(8), 0))
        self.scan_btn = ttk.Button(bar, text="Scan folder", style="Accent.TButton",
                                   command=self.do_scan)
        self.scan_btn.pack(side="right", padx=(px(8), 0))
        ttk.Button(bar, text="Browse\u2026", command=self._browse).pack(
            side="right", padx=(px(8), 0))
        entry = ttk.Entry(bar, textvariable=self.path, width=20)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda e: self.do_scan())

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True)
        side = _card(body)
        side.configure(width=px(430))
        side.pack(side="right", fill="y", padx=(px(12), 0))
        side.pack_propagate(False)
        ttk.Label(side, text="Largest files", style="CardHead.TLabel").pack(
            anchor="w", padx=px(14), pady=(px(12), px(8)))
        self.files = _Table(side, [
            ("size", "Size", px(80), "e"),
            ("folder", "Folder", px(170), "w"),
        ], tree_heading="File", tree_width=px(170),
            empty_text="Files over 1 MB appear here", caps={"#0": px(240)})
        self.files.pack(fill="both", expand=True)
        self.files.tree.bind("<Double-1>", self._open_location)

        mapcard = _card(body)
        mapcard.pack(side="left", fill="both", expand=True)
        self.crumb = ttk.Label(mapcard, text="", style="CardMuted.TLabel")
        self.crumb.pack(fill="x", padx=px(14), pady=(px(12), px(6)))
        self.canvas = tk.Canvas(mapcard, bg=COL_PANEL, highlightthickness=0, height=px(360),
                                cursor="hand2")
        self.canvas.pack(fill="both", expand=True, padx=px(10), pady=(0, px(10)))
        self.canvas.bind("<Button-1>", self._on_canvas_click)
        self.canvas.bind("<Configure>", lambda e: self._draw())

        self.progress = ttk.Progressbar(self, mode="indeterminate",
                                        style="Thin.Horizontal.TProgressbar")
        self.status = ttk.Label(self, text="Pick a folder and press Scan folder.",
                                style="Muted.TLabel", justify="left")
        self.status.pack(fill="x", pady=(px(8), 0))
        _autowrap(self.status, self, minus=px(4))

    def _browse(self) -> None:
        start = os.path.expandvars(self.path.get()) or "C:\\"
        chosen = filedialog.askdirectory(parent=self, initialdir=start,
                                         title="Choose a folder to measure")
        if chosen:
            self.path.set(os.path.normpath(chosen))

    def _open_location(self, event) -> None:
        iid = self.files.tree.identify_row(event.y)
        path = self._file_paths.get(iid)
        if not path or not base.IS_WINDOWS:
            return
        try:
            subprocess.Popen(["explorer", f"/select,{path}"])
        except OSError:
            pass

    def do_scan(self) -> None:
        if self.worker.busy:
            return
        target = os.path.abspath(os.path.expandvars(self.path.get()))
        if not os.path.isdir(target):
            messagebox.showerror("Sweep", f"Not a folder:\n{target}")
            return
        self.scan_btn.configure(state="disabled")
        self.progress.pack(fill="x", pady=(px(8), 0), before=self.status)
        self.progress.start(12)
        self.status.configure(text=f"Measuring {target}\u2026")
        want_dupes = self.dupes.get()

        def job(cancel, emit):
            tree = analyzer.build_tree(target, max_depth=3, cancel=cancel)
            big = analyzer.largest_files(target, limit=200, cancel=cancel)
            dupes = analyzer.find_duplicates(target, cancel=cancel) if want_dupes else []
            return tree, big, dupes

        def done(payload):
            tree, big, dupes = payload
            self.progress.stop()
            self.progress.pack_forget()
            self.scan_btn.configure(state="normal")
            self.root_node = tree
            self.view_node = tree
            self._draw()
            self.files.clear()
            self._file_paths.clear()
            for path, size in big:
                iid = self.files.add(os.path.basename(path),
                                     (base.human(size), os.path.dirname(path)))
                self._file_paths[iid] = path
            msg = f"{base.human(tree.size)} in {tree.file_count:,} files"
            if dupes:
                wasted = sum(g[0][1] * (len(g) - 1) for g in dupes)
                msg += (f"   \u00b7   {len(dupes)} duplicate group(s), "
                        f"{base.human(wasted)} reclaimable")
            if base.IS_WINDOWS and big:
                msg += "   \u00b7   double-click a file to show it in Explorer"
            self.status.configure(text=msg)

        def error(exc, tb):
            self.progress.stop()
            self.progress.pack_forget()
            self.scan_btn.configure(state="normal")
            self.status.configure(text="Scan failed")
            messagebox.showerror("Scan failed", f"{exc}\n\n{tb[-600:]}")

        self.worker.start(job, None, done, error)

    def go_up(self) -> None:
        node = self.view_node
        if not node or not self.root_node or node is self.root_node:
            return
        # find parent by path prefix
        target = os.path.dirname(node.path.rstrip("\\"))
        self.view_node = self._find(self.root_node, target) or self.root_node
        self._draw()

    def _find(self, node: analyzer.Node, path: str) -> analyzer.Node | None:
        if base.norm(node.path) == base.norm(path):
            return node
        for ch in node.children:
            if ch.is_dir and base.norm(path).startswith(base.norm(ch.path)):
                return self._find(ch, path)
        return None

    def _draw(self) -> None:
        self.canvas.delete("all")
        self.rects.clear()
        w = self.canvas.winfo_width() or 800
        h = self.canvas.winfo_height() or 380
        node = self.view_node
        if node is None:
            self.crumb.configure(text="No folder measured yet")
            self.canvas.create_text(w // 2, h // 2, fill=COL_SUBTLE, font=f(11),
                                    text="The map of the folder will appear here")
            return
        self.up_btn.configure(state="normal" if node is not self.root_node else "disabled")
        parts = [p for p in node.path.replace("/", "\\").split("\\") if p]
        self.crumb.configure(text="  \u203a  ".join(parts) + f"   \u00b7   {base.human(node.size)}")
        items = [(c.name, c.size) for c in node.children]
        if not items:
            self.canvas.create_text(w // 2, h // 2, text="(empty)",
                                    fill=COL_MUTED, font=f(11))
            return
        gap = px(2)
        rects = analyzer.squarify(items, 0, 0, w, h)
        sizes = {c.name: c.size for c in node.children}
        for i, (label, x, y, rw, rh) in enumerate(rects):
            if rw < 2 or rh < 2:
                continue
            color = PALETTE[i % len(PALETTE)]
            rid = self.canvas.create_rectangle(x + gap / 2, y + gap / 2,
                                               x + rw - gap / 2, y + rh - gap / 2,
                                               fill=color, outline="")
            self.rects.append((rid, x, y, rw, rh, label))
            if rw > px(72) and rh > px(38):
                maxc = max(4, int(rw / px(7)))
                name = label if len(label) <= maxc else label[:maxc - 1] + "\u2026"
                self.canvas.create_text(x + px(8), y + px(7), anchor="nw", fill="#f4f6f9",
                                        font=f(9, True), text=name)
                self.canvas.create_text(x + px(8), y + px(23), anchor="nw", fill="#e1e6ee",
                                        font=f(9), text=base.human(sizes.get(label, 0)))

    def _on_canvas_click(self, event) -> None:
        for rid, x, y, rw, rh, label in self.rects:
            if x <= event.x <= x + rw and y <= event.y <= y + rh:
                node = self.view_node
                if node is None:
                    return
                child = next((c for c in node.children if c.name == label), None)
                if child and child.is_dir and child.children:
                    self.view_node = child
                    self._draw()
                elif child and child.is_dir:
                    self.status.configure(
                        text=f"{child.path}  \u2014  scan this folder to see inside it")
                return


# --------------------------------------------------------------------------
# Startup page
# --------------------------------------------------------------------------

class StartupTab(ttk.Frame):
    TITLE = "Startup"
    DESC = ("Programs that start when you sign in. Disabling is reversible - Sweep "
            "sets the entry aside and puts it back when you enable it again.")

    def __init__(self, master, app) -> None:
        super().__init__(master, style="TFrame")
        self.app = app
        self.worker = Worker(self)
        self.items: list[system.StartupItem] = []
        self._build()

    def _build(self) -> None:
        _page_header(self, self.TITLE, self.DESC)
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, px(10)))
        self.refresh_btn = ttk.Button(bar, text="Refresh", style="Accent.TButton",
                                      command=self.refresh)
        self.refresh_btn.pack(side="left")
        ttk.Button(bar, text="Disable selected",
                   command=lambda: self._toggle(disable=True)).pack(side="left", padx=(px(8), 0))
        ttk.Button(bar, text="Enable selected",
                   command=lambda: self._toggle(disable=False)).pack(side="left", padx=(px(8), 0))
        self.svc = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Include services", variable=self.svc,
                        command=self.refresh).pack(side="left", padx=(px(16), 0))

        card = _card(self)
        card.pack(fill="both", expand=True)
        self.table = _Table(card, [
            ("state", "Status", px(80), "w"),
            ("kind", "Type", px(90), "w"),
            ("location", "Source", px(170), "w"),
            ("command", "Command", px(430), "w"),
        ], tree_heading="Name", tree_width=px(270), selectmode="browse",
            empty_text="Loading startup items\u2026", caps={"#0": px(440)})
        self.table.pack(fill="both", expand=True)
        self.tree = self.table.tree
        self.tree.tag_configure("off", foreground=COL_MUTED)
        self.tree.tag_configure("on", foreground=COL_FG)

        self.status = ttk.Label(self, text="", style="Muted.TLabel", justify="left")
        self.status.pack(fill="x", pady=(px(8), 0))
        _autowrap(self.status, self, minus=px(4))

    def refresh(self) -> None:
        if self.worker.busy:
            return
        self.status.configure(text="Reading startup entries\u2026")
        want_svc = self.svc.get()

        def job(cancel, emit):
            return system.list_startup(include_tasks=True, include_services=want_svc)

        def done(items):
            self.items = items
            self.table.clear()
            for idx, it in enumerate(items):
                self.table.add(
                    it.name, ("On" if it.enabled else "Off", it.kind, it.location,
                              it.command),
                    tag="on" if it.enabled else "off",
                    image=_img(self, f"dot:{COL_GREEN}" if it.enabled
                               else f"ring:{COL_SUBTLE}"),
                    iid=str(idx))
            if not items:
                self.table.set_empty("No startup entries found")
            text = f"{len(items)} item(s)   \u00b7   select one, then Disable or Enable"
            if system.TASK_ERROR:
                text = f"{len(items)} item(s)   \u00b7   {system.TASK_ERROR}"
            self.status.configure(text=text)
            self.app.set_status(f"{len(items)} startup item(s)", source=self)

        def error(exc, tb):
            self.status.configure(text="Could not read startup entries")
            messagebox.showerror("Startup", f"{exc}")

        self.worker.start(job, None, done, error)

    def _toggle(self, disable: bool) -> None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Sweep", "Select an item in the list first.")
            return
        item = self.items[int(sel[0])]
        verb = "Disable" if disable else "Enable"
        if not messagebox.askyesno(verb, f"{verb} {item.name}?\n\n"
                                         "This is reversible from this same screen.",
                                   icon="warning"):
            return
        msg = (system.disable_startup if disable else system.enable_startup)(item)
        self.status.configure(text=msg)
        self.refresh()


# --------------------------------------------------------------------------
# tool page shell: progress, elapsed timer, background work
# --------------------------------------------------------------------------

class _ToolPanel(ttk.Frame):
    TITLE = ""
    DESC = ""

    def __init__(self, master, app) -> None:
        super().__init__(master, style="TFrame")
        self.app = app
        self.worker = Worker(self)
        self._t0 = 0.0
        self._max = 0
        self._tick_job = None

        _page_header(self, self.TITLE, self.DESC)

        self.bar = ttk.Frame(self)
        self.bar.pack(fill="x", pady=(0, px(10)))
        self.build_controls(self.bar)

        card = _card(self)
        card.pack(fill="both", expand=True)
        self.body = ttk.Frame(card, style="Card.TFrame")
        self.body.pack(fill="both", expand=True)
        self.build_content(self.body)

        self.prow = ttk.Frame(self)
        self.prow.pack(fill="x")
        self.progress = ttk.Progressbar(self.prow, mode="determinate", maximum=100,
                                        style="Thin.Horizontal.TProgressbar")
        self.percent = ttk.Label(self.prow, text="", style="Muted.TLabel",
                                 width=5, anchor="e")

        frow = ttk.Frame(self)
        frow.pack(fill="x", pady=(px(8), 0))
        self.status = ttk.Label(frow, text="", style="Muted.TLabel", justify="left")
        self.status.pack(side="left", fill="x", expand=True)
        self.timer = ttk.Label(frow, text="", style="Muted.TLabel")
        self.timer.pack(side="right", anchor="n")
        _autowrap(self.status, frow, minus=px(90))

    # ---- subclass hooks -------------------------------------------------
    def build_controls(self, bar) -> None:
        pass

    def build_content(self, body) -> None:
        pass

    def on_show(self) -> None:
        """Called the first time the page is shown."""

    # ---- progress -------------------------------------------------------
    def start_progress(self, maximum: int | None = None, text: str = "working") -> None:
        self._t0 = time.time()
        self._max = int(maximum or 0)
        if self._max:
            self.progress.configure(mode="determinate", maximum=self._max, value=0)
        else:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
        if not self.progress.winfo_ismapped():
            self.progress.pack(side="left", fill="x", expand=True, pady=(px(10), 0))
            self.percent.pack(side="left", padx=(px(8), 0), pady=(px(10), 0))
        self.percent.configure(text="")
        self.set_status(text)
        self._tick()

    def _tick(self) -> None:
        if self._t0:
            self.timer.configure(text=f"{time.time() - self._t0:.1f}s")
            self._tick_job = self.after(200, self._tick)

    def update_progress(self, value: int | None = None, text: str | None = None) -> None:
        if value is not None and self._max:
            value = max(0, min(int(value), self._max))
            self.progress.configure(value=value)
            self.percent.configure(text=f"{int(value / self._max * 100)}%")
        if text:
            self.set_status(text)

    def end_progress(self, text: str | None = None) -> None:
        if self._tick_job:
            try:
                self.after_cancel(self._tick_job)
            except Exception:
                pass
            self._tick_job = None
        try:
            self.progress.stop()
        except tk.TclError:
            pass
        self.progress.pack_forget()
        self.percent.pack_forget()
        self._t0 = 0
        self._max = 0
        self.timer.configure(text="")
        if text:
            self.set_status(text)

    def set_status(self, text: str) -> None:
        try:
            self.status.configure(text=text)
        except tk.TclError:
            pass

    # ---- background execution -------------------------------------------
    def run(self, job, on_done=None, on_error=None, on_progress=None,
            maximum=None, text="working") -> None:
        if self.worker.busy:
            self.set_status("busy - wait for the current job")
            return
        self.start_progress(maximum=maximum, text=text)

        def progress(done, total, label=None, extra=None):
            if on_progress:
                on_progress(done, total, label, extra)
            else:
                self.update_progress(done, label)

        def done(result):
            self.end_progress()
            if on_done:
                on_done(result)

        def error(exc, tb):
            self.end_progress()
            self.set_status("failed")
            if on_error:
                on_error(exc, tb)
            else:
                messagebox.showerror("Sweep", f"{exc}\n\n{tb[-400:]}", parent=self)

        self.worker.start(job, progress, done, error)


# --------------------------------------------------------------------------
# tool pages
# --------------------------------------------------------------------------

class SchedulePanel(_ToolPanel):
    TITLE = "Automatic cleaning"
    DESC = ("Registers one Windows scheduled task that runs Sweep's clean "
            "unattended. Same rules as the Clean page's recommended set, an audit "
            "log each run, and one click to remove it.")

    def build_controls(self, bar) -> None:
        ttk.Label(bar, text="Run").pack(side="left")
        self.freq = ttk.Combobox(bar, values=["daily", "weekly", "logon", "idle"],
                                 width=9, state="readonly")
        self.freq.set("weekly")
        self.freq.pack(side="left", padx=(px(8), px(8)))
        ttk.Label(bar, text="at").pack(side="left")
        self.at = ttk.Entry(bar, width=7)
        self.at.insert(0, "12:00")
        self.at.pack(side="left", padx=(px(8), 0))
        ttk.Button(bar, text="Schedule", style="Accent.TButton",
                   command=self.install).pack(side="left", padx=(px(14), 0))
        ttk.Button(bar, text="Remove", command=self.remove).pack(side="left", padx=(px(8), 0))
        ttk.Button(bar, text="Check status", command=self.check_status).pack(
            side="left", padx=(px(8), 0))

    def build_content(self, body) -> None:
        self.table = _Table(body, [
            ("value", "Value", px(420), "w"),
        ], tree_heading="Setting", tree_width=px(220), selectmode="none",
            empty_text="Press Check status to see whether automatic cleaning is set up")
        self.table.pack(fill="both", expand=True)

    def _fill(self, st) -> None:
        self.table.clear()
        if getattr(st, "error", ""):
            self.table.add("State", ("could not be read",), tag="warn")
            self.table.add("Reason", (st.error,), tag="muted")
            self.set_status("Task Scheduler could not be read, so Sweep cannot tell "
                            "whether a clean is scheduled")
            return
        if not st.installed:
            self.table.add("State", ("not scheduled",), tag="muted")
            self.set_status("no scheduled clean is registered")
            return
        self.table.add("State", (("enabled" if st.enabled else "disabled"),),
                       tag="ok" if st.enabled else "warn")
        self.table.add("Next run", ((st.next_run or "-"),))
        self.table.add("Last run", ((st.last_run or "-"),))
        self.table.add("Last result", ((st.last_result or "-"),))
        self.set_status("scheduled" if st.enabled else "scheduled but disabled")

    def install(self) -> None:
        from . import schedule
        freq = self.freq.get()
        at = self.at.get().strip() or "12:00"
        self.run(lambda cancel, emit: schedule.create(freq, at),
                 on_done=lambda r: self._report(*r), text="registering task")

    def remove(self) -> None:
        from . import schedule
        self.run(lambda cancel, emit: schedule.remove(),
                 on_done=lambda r: self._report(*r), text="removing task")

    def check_status(self) -> None:
        from . import schedule
        self.run(lambda cancel, emit: schedule.status(),
                 on_done=self._fill, text="reading task state")

    def _report(self, ok, msg) -> None:
        self.set_status(("ok: " if ok else "failed: ") + msg)
        self.check_status()


class AppsPanel(_ToolPanel):
    TITLE = "Applications"
    DESC = ("Installed programs with their real size on disk. Sweep runs the "
            "vendor's own uninstaller - it never deletes an install folder itself. "
            "Leftovers are advisory.")

    def build_controls(self, bar) -> None:
        ttk.Button(bar, text="Load applications", style="Accent.TButton",
                   command=self.list_apps).pack(side="left")
        self.filter = ttk.Entry(bar, width=28)
        self.filter.pack(side="left", padx=(px(8), 0))
        _placeholder(self.filter, "Filter by name")
        self.filter.bind("<Return>", lambda e: self.list_apps())
        ttk.Button(bar, text="Uninstall selected",
                   command=self.uninstall).pack(side="left", padx=(px(14), 0))
        ttk.Button(bar, text="Find leftovers", command=self.leftovers).pack(
            side="left", padx=(px(8), 0))

    def build_content(self, body) -> None:
        self.table = _Table(body, [
            ("version", "Version", px(120), "w"),
            ("publisher", "Publisher", px(190), "w"),
            ("size", "Size", px(100), "e"),
        ], tree_heading="Program", tree_width=px(300),
            empty_text="Press Load applications to list installed programs")
        self.table.pack(fill="both", expand=True)
        self._apps: dict[str, object] = {}

    def _needle(self) -> str:
        return _entry_value(self.filter).lower()

    def list_apps(self) -> None:
        from . import apps as appmod
        needle = self._needle()

        def job(cancel, emit):
            items = appmod.list_apps()
            if needle:
                items = [a for a in items if needle in a.name.lower()]
            total = len(items)
            emit(0, total, f"{total} application(s)")
            for i, a in enumerate(items):
                if cancel.is_set():
                    break
                size = appmod.app_size(a)
                emit(i + 1, total, a.name, (a, size))
            return items

        self.table.clear()
        self._apps.clear()

        def progress(done, total, label, extra):
            self.update_progress(done, label or "")
            if extra:
                a, size = extra
                iid = self.table.add(a.name, (
                    a.version, a.publisher or "",
                    base.human(size) if size else "\u2013"))
                self._apps[iid] = a

        def done(items):
            self.set_status(f"{len(items)} application(s)   \u00b7   select one to "
                            "uninstall it or look for leftovers")
            if not items:
                self.table.set_empty("No programs match the filter")

        self.run(job, on_done=done, on_progress=progress,
                 maximum=None, text="reading installed programs\u2026")

    def _selected_app(self):
        sel = self.table.selected()
        if not sel:
            return None
        return self._apps.get(sel[0])

    def uninstall(self) -> None:
        from . import apps as appmod
        a = self._selected_app()
        if a is None:
            messagebox.showinfo("Sweep", "Select a program in the list first.",
                                parent=self)
            return
        if not a.uninstallable:
            messagebox.showwarning("Sweep", f"{a.name} has no uninstall command "
                                            "registered.", parent=self)
            return
        if not messagebox.askyesno(
                "Uninstall", f"Run the uninstaller for:\n\n{a.name}\n\n"
                "Sweep starts the vendor's uninstaller and does not delete "
                "files itself.", parent=self):
            return
        ok, info = appmod.launch_uninstall(a)
        self.set_status(("started: " if ok else "failed: ") + info)

    def leftovers(self) -> None:
        from . import apps as appmod
        a = self._selected_app()
        needle = a.name.lower() if a else self._needle()
        if not needle:
            messagebox.showinfo("Sweep", "Select a program or type a filter first.",
                                parent=self)
            return

        def job(cancel, emit):
            target = a
            if target is None:
                match = [x for x in appmod.list_apps() if needle in x.name.lower()]
                if not match:
                    return (None, [])
                target = match[0]
            emit(0, 1, target.name)
            return (target, appmod.find_leftovers(target))

        def done(result):
            target, left = result
            self.table.clear()
            if target is None:
                self.set_status("no matching program")
                self.table.set_empty("No matching program")
                return
            self.table.add(target.name, (target.version, "leftovers:", ""),
                           tag="warn")
            for lo in left:
                size = base.human(lo.size) if lo.size else ""
                self.table.add(lo.path, (lo.kind, lo.matched, size),
                               tag="warn")
            self.set_status(f"{len(left)} leftover item(s) for {target.name} - "
                            "review before deleting")

        self.run(job, on_done=done, on_progress=None,
                 text="looking for leftovers\u2026")


class DriversPanel(_ToolPanel):
    TITLE = "Drivers"
    DESC = ("Installed kernel drivers, and driver updates that Windows Update is "
            "offering. No third-party driver catalogue is used: only signed, "
            "hardware-matched packages.")

    def build_controls(self, bar) -> None:
        ttk.Button(bar, text="Scan installed", style="Accent.TButton",
                   command=self.inventory).pack(side="left")
        ttk.Button(bar, text="Check Windows Update",
                   command=self.check).pack(side="left", padx=(px(8), 0))
        self.install_btn = ttk.Button(bar, text="Install selected",
                                      command=self.install, state="disabled")
        self.install_btn.pack(side="left", padx=(px(8), 0))
        self.count = ttk.Label(bar, text="", style="Muted.TLabel")
        self.count.pack(side="left", padx=px(12))

    def build_content(self, body) -> None:
        seg = ttk.Frame(body, style="Card.TFrame")
        seg.pack(fill="x", padx=px(10), pady=(px(10), px(8)))
        self.seg_installed = ttk.Button(seg, text="Installed", style="SegOn.TButton",
                                        command=lambda: self._view("installed"))
        self.seg_installed.pack(side="left")
        self.seg_available = ttk.Button(seg, text="Available updates", style="Seg.TButton",
                                        command=lambda: self._view("available"))
        self.seg_available.pack(side="left", padx=(px(4), 0))
        self.views = ttk.Frame(body, style="Card.TFrame")
        self.views.pack(fill="both", expand=True)
        self.installed = _Table(self.views, [
            ("type", "Type", px(150), "w"),
            ("start", "Start", px(110), "w"),
            ("path", "Image path", px(420), "w"),
        ], tree_heading="Driver", tree_width=px(280), selectmode="none",
            empty_text="Press Scan installed to list kernel drivers")
        self.available = _CheckList(self.views, [
            ("detail", "Offered", px(260), "w"),
            ("result", "Result", px(130), "w"),
        ], tree_heading="Driver update", tree_width=px(320),
            on_change=self._on_change,
            empty_text="Press Check Windows Update to see offered driver updates")
        self.notice = _Notice(body)
        self._view("installed")

    def _view(self, which: str) -> None:
        show, hide = ((self.installed, self.available) if which == "installed"
                      else (self.available, self.installed))
        hide.pack_forget()
        show.pack(fill="both", expand=True)
        self.seg_installed.configure(style="SegOn.TButton" if which == "installed"
                                     else "Seg.TButton")
        self.seg_available.configure(style="SegOn.TButton" if which == "available"
                                     else "Seg.TButton")

    def _on_change(self, checked) -> None:
        n = len(checked)
        self.count.configure(text=f"{n} selected" if n else "")
        self.install_btn.configure(
            state="normal" if n and not self.worker.busy else "disabled",
            style="Accent.TButton" if n else "TButton")

    def inventory(self) -> None:
        from . import drivers

        def job(cancel, emit):
            items = drivers.inventory()
            emit(0, 1, f"{len(items)} driver(s)")
            return items

        def done(items):
            self._view("installed")
            self.installed.clear()
            for d in items:
                self.installed.add(d.display_name or d.module_name,
                                   (d.driver_type, d.start_mode, d.path))
            self.set_status(f"{len(items)} kernel driver(s) installed")

        self.run(job, on_done=done, text="reading driver registry\u2026")

    def check(self) -> None:
        from . import winupdate

        def job(cancel, emit):
            emit(0, 1, "asking Windows Update\u2026")
            return winupdate.search()

        def done(result):
            items, err = result
            self._view("available")
            self.available.clear()
            if err:
                self.available.set_empty("Driver updates were not checked, so Sweep "
                                         "cannot say whether your drivers are current.")
                action = (("Restart as administrator", self.app._elevate)
                          if not base.is_admin() and _needs_admin(err) else None)
                self.notice.show("Windows Update could not be checked.\n" + err, action,
                                 fill="x", padx=px(10), pady=(0, px(8)),
                                 before=self.views)
                self.set_status("driver updates not checked")
                return
            self.notice.hide()
            for u in items:
                if not u.is_driver:
                    continue
                self.available.add(u.update_id, u.title,
                                   (f"{u.size_mb:.0f} MB \u00b7 {u.categories}", ""),
                                   payload=u)
            n = len(self.available.checked())
            if not n:
                self.available.set_empty("Windows Update offers no driver updates")
            self.set_status(f"{n} driver update(s) offered" if n
                            else "Windows Update offers no driver updates")

        self.run(job, on_done=done, text="querying Windows Update\u2026")

    def install(self) -> None:
        from . import winupdate
        chosen = [m for m in self.available.checked() if m.get("payload")]
        if not chosen:
            return
        if not messagebox.askyesno(
                "Install drivers",
                f"Install {len(chosen)} driver update(s) from Windows Update?\n\n"
                "The screen may flicker. Device Manager can roll back.", parent=self):
            return
        total = len(chosen)
        rows = list(self.available.rows_meta.items())

        def job(cancel, emit):
            outcomes = []
            for i, (iid, meta) in enumerate(rows):
                if not meta["checked"] or not meta.get("payload"):
                    continue
                upd = meta["payload"]
                ok, msg, _outs, _reboot = winupdate.install([upd.update_id])
                outcomes.append((meta["key"], ok, msg))
                emit(i + 1, total, upd.title[:60])
            return outcomes

        def progress(done, total_, label, extra):
            self.update_progress(done, label or "")
            for iid, meta in rows:
                if meta["checked"] and meta.get("payload") and \
                        meta["payload"].title[:60] == label:
                    self.available.toggle(iid)

        def done(outcomes):
            for key, ok, msg in outcomes:
                for iid, meta in self.available.rows_meta.items():
                    if meta["key"] == key:
                        self.available.mark(iid, "result",
                                            ("ok " if ok else "failed ") + msg,
                                            "ok" if ok else "bad")
            good = sum(1 for _k, ok, _m in outcomes if ok)
            self.set_status(f"{good}/{len(outcomes)} driver update(s) installed")
            self._on_change(self.available.checked())

        self.run(job, on_done=done, on_progress=progress, maximum=total,
                 text="installing drivers\u2026")


class UpdatesPanel(_ToolPanel):
    TITLE = "Updates"
    DESC = ("One list across software, Windows and drivers. Tick exactly what you "
            "want, then install. Software uses winget; Windows and drivers use "
            "Windows Update and need administrator rights.")

    def build_controls(self, bar) -> None:
        self.check_btn = ttk.Button(bar, text="Check for updates",
                                    style="Accent.TButton", command=self.check)
        self.check_btn.pack(side="left")
        self.install_btn = ttk.Button(bar, text="Install selected",
                                      command=self.install, state="disabled")
        self.install_btn.pack(side="left", padx=(px(8), 0))
        self.want_sw = tk.BooleanVar(value=True)
        self.want_win = tk.BooleanVar(value=True)
        self.want_drv = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Software", variable=self.want_sw).pack(
            side="left", padx=(px(18), 0))
        ttk.Checkbutton(bar, text="Windows", variable=self.want_win).pack(
            side="left", padx=(px(12), 0))
        ttk.Checkbutton(bar, text="Drivers", variable=self.want_drv).pack(
            side="left", padx=(px(12), 0))
        self.count = ttk.Label(bar, text="", style="Muted.TLabel")
        self.count.pack(side="right")
        ttk.Button(bar, text="None", style="Link.TButton",
                   command=lambda: self.list.set_all(False)).pack(side="right",
                                                                 padx=(0, px(10)))
        ttk.Button(bar, text="All", style="Link.TButton",
                   command=lambda: self.list.set_all(True)).pack(side="right")
        ttk.Label(bar, text="Select", style="Muted.TLabel").pack(side="right")

    def build_content(self, body) -> None:
        self.list = _CheckList(body, [
            ("source", "Source", px(80), "w"),
            ("detail", "Available", px(200), "w"),
            ("result", "Result", px(140), "w"),
        ], tree_heading="Update", tree_width=px(300),
            on_change=self._on_change, on_row_click=self._show_message,
            empty_text="Press Check for updates to search all three sources")
        self.list.pack(fill="both", expand=True)
        self.notice = _Notice(body)
        self.detail = ttk.Label(body, text="Click a row to tick or untick it. After an "
                                           "install, click a row to read its full "
                                           "result here.",
                                style="CardMuted.TLabel", justify="left",
                                wraplength=px(900))
        self.detail.pack(fill="x", padx=px(14), pady=px(10))

    def _show_message(self, meta: dict) -> None:
        msg = meta.get("message") or ""
        if msg:
            self.detail.configure(text=msg)
        else:
            self.detail.configure(text=f"{meta.get('label','')} - no message yet")

    def _on_change(self, checked) -> None:
        n = len(checked)
        self.count.configure(text=f"{n} selected" if n else "")
        self.install_btn.configure(
            state="normal" if n and not self.worker.busy else "disabled",
            style="Accent.TButton" if n else "TButton")
        self.check_btn.configure(style="TButton" if n else "Accent.TButton")

    # ---- gather ---------------------------------------------------------
    def check(self) -> None:
        want_sw = self.want_sw.get()
        want_win = self.want_win.get()
        want_drv = self.want_drv.get()
        if not (want_sw or want_win or want_drv):
            self.list.clear()
            self.notice.hide()
            self.list.set_empty("Nothing was checked. Tick Software, Windows or Drivers, "
                                "then press Check for updates.")
            self.set_status("nothing checked - no source is ticked")
            return
        asked = [name for name, want in (("Software", want_sw), ("Windows", want_win),
                                         ("Drivers", want_drv)) if want]

        def job(cancel, emit):
            from . import apps as appmod, winupdate
            failed: dict[str, str] = {}          # source -> why it was not checked
            software = windows = driver = []
            if want_sw:
                emit(0, 1, "checking winget\u2026")
                ok, detail = appmod.winget_diagnose()
                if ok:
                    software, err = appmod.list_upgrades()
                    if err:
                        failed["Software"] = "winget: " + err
                else:
                    failed["Software"] = "winget: " + detail
            if want_win or want_drv:
                emit(0, 1, "checking Windows Update\u2026")
                items, err = winupdate.search()
                if err:
                    for name, want in (("Windows", want_win), ("Drivers", want_drv)):
                        if want:
                            failed[name] = "Windows Update: " + err
                else:
                    if want_win:
                        windows = [u for u in items if not u.is_driver]
                    if want_drv:
                        driver = [u for u in items if u.is_driver]
            return {"software": software, "windows": windows,
                    "drivers": driver, "failed": failed}

        def done(payload):
            self.list.clear()
            sw = payload["software"]
            win = payload["windows"]
            drv = payload["drivers"]
            for u in sw:
                self.list.add("sw:" + u.package_id, u.name,
                              ("winget", f"{u.current}  \u2192  {u.available}", ""),
                              payload={"kind": "winget", "id": u.package_id,
                                       "name": u.name})
            for u in win:
                self.list.add("wu:" + u.update_id, u.title,
                              ("Windows",
                               f"{u.size_mb:.0f} MB \u00b7 {u.kb or 'no KB'}",
                               ""),
                              payload={"kind": "windows", "id": u.update_id,
                                       "name": u.title})
            for u in drv:
                self.list.add("wu:" + u.update_id, u.title,
                              ("driver", f"{u.size_mb:.0f} MB", ""),
                              payload={"kind": "driver", "id": u.update_id,
                                       "name": u.title})
            total = len(sw) + len(win) + len(drv)
            failed = payload["failed"]
            checked = [n for n in asked if n not in failed]
            missed = [n for n in asked if n in failed]

            # The one message this page must never get wrong: a source that could
            # not be reached is "unknown", never "up to date".
            if failed:
                reasons = list(dict.fromkeys(failed.values()))
                verb = "was" if len(missed) == 1 else "were"
                text = (f"{_join(missed)} {verb} not checked, so Sweep cannot say "
                        f"whether {'it is' if len(missed) == 1 else 'they are'} up to "
                        "date.\n" + "\n".join(reasons))
                action = None
                if not base.is_admin() and any(_needs_admin(r) for r in reasons):
                    action = ("Restart as administrator", self.app._elevate)
                self.notice.show(text, action, fill="x", padx=px(10),
                                 pady=(px(10), 0), before=self.list)
            else:
                self.notice.hide()

            notes = list(dict.fromkeys(failed.values()))
            empty = update_empty_message(total, notes, checked=checked, missed=missed)
            if empty:
                self.list.set_empty(empty)
            self.set_status(update_summary(total, notes, missed=missed))

        self.run(job, on_done=done, text="checking all sources\u2026")

    # ---- install --------------------------------------------------------
    def install(self) -> None:
        chosen = [m for m in self.list.checked() if m.get("payload")]
        if not chosen:
            return
        if not messagebox.askyesno(
                "Install updates",
                f"Install {len(chosen)} selected update(s)?\n\n"
                "A restart may be required afterwards.", parent=self):
            return
        items = [(iid, meta) for iid, meta in self.list.rows_meta.items()
                 if meta["checked"] and meta.get("payload")]
        total = len(items)

        def job(cancel, emit):
            from . import apps as appmod, winupdate
            results = []
            for i, (iid, meta) in enumerate(items):
                if cancel.is_set():
                    break
                p = meta["payload"]
                if p["kind"] == "winget":
                    ok, msg = appmod.upgrade_package(p["id"])
                else:
                    ok, msg, _outs, _reboot = winupdate.install([p["id"]])
                results.append((meta["key"], ok, msg))
                emit(i + 1, total, p["name"][:60], meta["key"])
            return results

        def progress(done, total_, label, extra):
            self.update_progress(done, label or "")
            if extra:
                for iid, meta in items:
                    if meta["key"] == extra:
                        self.list.set(iid, "result", "running\u2026")

        def done(results):
            from . import apps as appmod
            by_key = {k: (ok, msg) for k, ok, msg in results}
            for iid, meta in items:
                ok, msg = by_key.get(meta["key"], (False, "not run"))
                label = appmod.short_status(ok, msg)
                explanation = appmod.explain_winget_error(msg) if not ok else ""
                detail = ("installed successfully" if ok else
                          (f"{explanation}\n\nwinget said: {msg}" if explanation
                           else msg))
                self.list.mark(iid, "result", label, "ok" if ok else "bad",
                               message=f"{meta['label']} - {detail}")
                if ok:
                    self.list.set_checked(iid, False)
            good = sum(1 for ok, _m in by_key.values() if ok)
            self.set_status(f"{good}/{len(results)} installed")
            self._on_change(self.list.checked())

        self.run(job, on_done=done, on_progress=progress, maximum=total,
                 text="installing updates\u2026")


class SecurePanel(_ToolPanel):
    TITLE = "Secure erase"
    DESC = ("Overwrite before deleting, or fill a drive's free space and remove it. "
            "On an SSD this cannot guarantee the original cells are gone - only "
            "BitLocker key destruction or the drive's own Secure Erase can do that.")

    def build_controls(self, bar) -> None:
        # packed right-to-left so the path entry takes whatever width is left
        ttk.Button(bar, text="Wipe free space",
                   command=self.free_space).pack(side="right", padx=(px(8), 0))
        ttk.Button(bar, text="Wipe files", style="Accent.TButton",
                   command=self.wipe).pack(side="right", padx=(px(14), 0))
        self.passes = ttk.Combobox(bar, values=["1 pass", "3 passes"], width=9,
                                   state="readonly")
        self.passes.set("3 passes")
        self.passes.pack(side="right", padx=(px(14), 0))
        ttk.Button(bar, text="Folder\u2026", command=self._pick_folder).pack(
            side="right", padx=(px(6), 0))
        ttk.Button(bar, text="File\u2026", command=self._pick_file).pack(
            side="right", padx=(px(8), 0))
        self.target = ttk.Entry(bar, width=16)
        self.target.pack(side="left", fill="x", expand=True)
        _placeholder(self.target, "File or folder to wipe")

    def build_content(self, body) -> None:
        self.table = _Table(body, [
            ("result", "Result", px(350), "w"),
        ], tree_heading="File", tree_width=px(360), selectmode="none",
            empty_text="Wiped files are listed here")
        self.table.pack(fill="both", expand=True)

    def _pick_file(self) -> None:
        p = filedialog.askopenfilename(parent=self, title="Choose a file to wipe")
        if p:
            _set_entry(self.target, os.path.normpath(p))

    def _pick_folder(self) -> None:
        p = filedialog.askdirectory(parent=self, title="Choose a folder to wipe")
        if p:
            _set_entry(self.target, os.path.normpath(p))

    def _target(self) -> str:
        return os.path.expandvars(_entry_value(self.target))

    def wipe(self) -> None:
        from . import secure
        p = self._target()
        if not p:
            messagebox.showinfo("Sweep", "Choose a file or folder first.", parent=self)
            return
        if not os.path.exists(p):
            messagebox.showerror("Sweep", f"Not found:\n{p}", parent=self)
            return
        passes = int((self.passes.get() or "1").split()[0])
        files = [p] if os.path.isfile(p) else [f for f, _ in base.walk(p, "*", recurse=True)]
        if not files:
            self.set_status("nothing to wipe")
            return
        total = sum(os.path.getsize(f) for f in files if os.path.exists(f))
        if not messagebox.askyesno(
                "Secure erase",
                f"Overwrite and delete {len(files)} file(s), {base.human(total)}, "
                f"{passes} pass(es)?\n\nThis cannot be undone.", parent=self,
                icon="warning"):
            return

        def job(cancel, emit):
            done = failed = 0
            for i, f in enumerate(files):
                if cancel.is_set():
                    break
                r = secure.wipe_file(f, passes=passes)
                if r.ok:
                    done += 1
                else:
                    failed += 1
                emit(i + 1, len(files), os.path.basename(f), r)
            return done, failed

        self.table.clear()

        def progress(done, total_, label, extra):
            self.update_progress(done, label or "")
            if isinstance(extra, secure.WipeResult):
                self.table.add(os.path.basename(extra.path),
                               ("wiped  " + base.human(extra.size) if extra.ok
                                else "failed  " + (extra.error or ""),),
                               tag="ok" if extra.ok else "bad")

        def done(result):
            ok, failed = result
            self.set_status(f"wiped {ok} file(s)" + (f", {failed} failed" if failed else ""))
            if secure.is_ssd(os.path.abspath(files[0])) is True:
                self.set_status(f"wiped {ok} file(s) - note: SSD, see the caveat above")

        self.run(job, on_done=done, on_progress=progress, maximum=len(files),
                 text="wiping\u2026")

    def free_space(self) -> None:
        from . import secure
        p = self._target() or os.path.expandvars("%SystemDrive%\\")
        root = p if os.path.isdir(p) else os.path.splitdrive(os.path.abspath(p))[0] + "\\"
        if not messagebox.askyesno(
                "Wipe free space",
                f"Fill the free space on {root} with random data, then remove it?"
                "\n\nThis takes a while. The volume stays usable.",
                parent=self, icon="warning"):
            return

        def job(cancel, emit):
            def cb(written, budget):
                emit(written, budget, f"{base.human(written)} / {base.human(budget)}")
            return secure.wipe_free_space(root, cancel=cancel, progress=cb)

        def progress(done, total_, label, extra):
            self.update_progress(done, label or "")

        def done(result):
            written, files, note = result
            self.set_status(note)

        self.run(job, on_done=done, on_progress=progress, maximum=100,
                 text="overwriting free space\u2026")


class KeepPanel(_ToolPanel):
    TITLE = "Cookie keep-list"
    DESC = ("Sites listed here keep their cookies when the Privacy cookie rule "
            "runs, so you stay signed in where you choose.")

    def build_controls(self, bar) -> None:
        self.domain = ttk.Entry(bar, width=32)
        self.domain.pack(side="left")
        _placeholder(self.domain, "example.com")
        self.domain.bind("<Return>", lambda e: self.add())
        ttk.Button(bar, text="Add", style="Accent.TButton",
                   command=self.add).pack(side="left", padx=(px(8), 0))
        ttk.Button(bar, text="Remove", command=self.remove).pack(side="left", padx=(px(8), 0))
        ttk.Button(bar, text="Refresh", command=self.show).pack(side="left", padx=(px(8), 0))

    def build_content(self, body) -> None:
        self.table = _Table(body, [
            ("kind", "Kind", px(100), "w"),
            ("detail", "Detail", px(310), "w"),
        ], tree_heading="Kept site / detected cookie store", tree_width=px(300),
            selectmode="browse")
        self.table.pack(fill="both", expand=True)
        self.table.tree.bind("<<TreeviewSelect>>", self._on_select)
        self._shown = False

    def on_show(self) -> None:
        if not self._shown:
            self.show()

    def _on_select(self, _e=None) -> None:
        sel = self.table.selected()
        if not sel:
            return
        values = self.table.tree.item(sel[0], "values")
        if values and values[0] == "protected":
            _set_entry(self.domain, self.table.tree.item(sel[0], "text").strip())

    def _domain(self) -> str:
        return _entry_value(self.domain)

    def add(self) -> None:
        from . import keep
        d = self._domain()
        if not d:
            self.set_status("type a site such as github.com first")
            return
        kl = keep.KeepList.load()
        kl.add(d)
        kl.save()
        self.show()
        self.app.refresh_facts()

    def remove(self) -> None:
        from . import keep
        d = self._domain()
        if not d:
            self.set_status("select or type the site to remove")
            return
        kl = keep.KeepList.load()
        kl.remove(d)
        kl.save()
        self.show()
        self.app.refresh_facts()

    def show(self) -> None:
        from . import keep
        self._shown = True
        kl = keep.KeepList.load()
        dbs = keep.candidate_dbs()
        self.table.clear()
        if not kl.domains:
            self.table.add("(none)", ("empty", "every cookie will be removed"),
                           tag="warn")
        for d in kl.domains:
            self.table.add(d, ("protected", ""), tag="ok")
        for label, path in dbs:
            self.table.add(label, ("store", path), tag="muted")
        self.set_status(f"{len(kl.domains)} site(s) protected \u00b7 "
                        f"{len(dbs)} cookie store(s) detected")


class ToolsTab(_Stack):
    """The tool pages. Each one has its own sidebar entry; this container keeps
    them together and still answers select(i) / tabs() like the old notebook."""

    PANELS = (SchedulePanel, AppsPanel, DriversPanel, UpdatesPanel,
              SecurePanel, KeepPanel)

    def __init__(self, master, app, on_change=None) -> None:
        super().__init__(master, on_change=on_change)
        self.app = app
        self.panels: dict[str, _ToolPanel] = {}
        for cls in self.PANELS:
            panel = cls(self, app)
            self.add(panel, text=cls.TITLE)
            self.panels[cls.TITLE] = panel


# --------------------------------------------------------------------------
# Health page
# --------------------------------------------------------------------------

_STATUS_COLOR = {"ok": COL_GREEN, "warn": COL_AMBER, "bad": COL_RED,
                 "unknown": COL_MUTED}
_STATUS_LABEL = {"ok": "OK", "warn": "Warning", "bad": "Problem", "unknown": "Unknown"}


class HealthTab(ttk.Frame):
    TITLE = "Health"
    DESC = ("Twelve checks on whether this PC is degrading. Save snapshots to see "
            "the trend over time.")

    def __init__(self, master, app) -> None:
        super().__init__(master, style="TFrame")
        self.app = app
        self.worker = Worker(self)
        self.checks = []
        self._build()

    def _build(self) -> None:
        actions = _page_header(self, self.TITLE, self.DESC)
        self.run_btn = ttk.Button(actions, text="Run health check",
                                  style="Accent.TButton", command=self.refresh)
        self.run_btn.pack(side="right")
        ttk.Button(actions, text="Save snapshot", command=self.snapshot).pack(
            side="right", padx=(0, px(8)))

        hero = _card(self)
        hero.pack(fill="x")
        inner = tk.Frame(hero, bg=COL_PANEL)
        inner.pack(fill="x", padx=px(22), pady=px(12))
        self.score_lbl = ttk.Label(inner, text="\u2013", style="Score.TLabel")
        self.score_lbl.pack(side="left")
        words = tk.Frame(inner, bg=COL_PANEL)
        words.pack(side="left", padx=(px(16), 0))
        self.verdict_lbl = ttk.Label(words, text="Not measured yet", style="CardHead.TLabel")
        self.verdict_lbl.pack(anchor="w")
        self.counts_lbl = ttk.Label(words, text="Press Run health check.",
                                    style="CardMuted.TLabel")
        self.counts_lbl.pack(anchor="w", pady=(px(2), 0))
        self.status = ttk.Label(inner, text="", style="CardMuted.TLabel")
        self.status.pack(side="right", anchor="s")

        self.notice = _Notice(self)
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, pady=(px(12), 0))
        self._body = body

        advice_card = _card(body)
        advice_card.configure(width=px(390))
        advice_card.pack(side="right", fill="y", padx=(px(12), 0))
        advice_card.pack_propagate(False)
        body.bind("<Configure>", lambda e: advice_card.configure(
            width=max(px(290), min(px(420), int(e.width * 0.4)))))
        ttk.Label(advice_card, text="What to do", style="CardHead.TLabel").pack(
            anchor="w", padx=px(16), pady=(px(12), px(6)))
        wrap = tk.Frame(advice_card, bg=COL_PANEL)
        wrap.pack(fill="both", expand=True, padx=(px(16), px(4)), pady=(0, px(10)))
        self.advice = tk.Text(wrap, bg=COL_PANEL, fg=COL_FG, bd=0, height=7, width=10,
                              font=f(10), wrap="word", highlightthickness=0,
                              insertbackground=COL_FG, padx=0, pady=px(2),
                              cursor="arrow", spacing1=px(1), spacing3=px(1))
        avs = ttk.Scrollbar(wrap, orient="vertical", command=self.advice.yview)
        self.advice.configure(yscrollcommand=avs.set)
        self.advice.pack(side="left", fill="both", expand=True)
        avs.pack(side="right", fill="y")
        for st, col in _STATUS_COLOR.items():
            self.advice.tag_configure("h_" + st, foreground=col, font=f(10, True))
        self.advice.tag_configure("value", foreground=COL_MUTED)
        self.advice.tag_configure("body", foreground=COL_FG, spacing1=px(2))
        self.advice.tag_configure("detail", foreground=COL_MUTED, font=f(9),
                                  lmargin1=px(4), lmargin2=px(16))
        self.advice.tag_configure("muted", foreground=COL_MUTED)
        self.advice.insert("end", "Advice for anything that needs attention appears here.",
                           "muted")
        self.advice.configure(state="disabled")

        card = _card(body)
        card.pack(side="left", fill="both", expand=True)
        self.table = _Table(card, [
            ("state", "Status", px(80), "w"),
            ("value", "Result", px(200), "w"),
        ], tree_heading="Check", tree_width=px(180), selectmode="browse",
            empty_text="Run the health check to measure this PC")
        self.table.pack(fill="both", expand=True)
        self.tree = self.table.tree

    def refresh(self) -> None:
        if self.worker.busy:
            return
        from . import health
        self.run_btn.configure(state="disabled")
        self.status.configure(text="Measuring\u2026")
        self.app.set_status("running health checks\u2026", source=self)

        def job(cancel, emit):
            return health.run_checks()

        def done(checks):
            self.checks = checks
            self.run_btn.configure(state="normal")
            sc = health.score(checks)
            col = COL_GREEN if sc >= 90 else COL_AMBER if sc >= 55 else COL_RED
            self.score_lbl.configure(text=str(sc), foreground=col)
            self.verdict_lbl.configure(text=health.verdict(sc).capitalize()
                                       + "   \u00b7   score out of 100")
            n = {k: sum(1 for c in checks if c.status == k) for k in _STATUS_LABEL}
            parts = []
            if n["bad"]:
                parts.append(f"{n['bad']} problem{'s' if n['bad'] != 1 else ''}")
            if n["warn"]:
                parts.append(f"{n['warn']} warning{'s' if n['warn'] != 1 else ''}")
            if n["unknown"]:
                parts.append(f"{n['unknown']} could not be read")
            parts.append(f"{n['ok']} OK")
            self.counts_lbl.configure(text="   \u00b7   ".join(parts))
            self.status.configure(text=time.strftime("measured %H:%M"))
            self.app.set_status(f"health score {sc}/100", source=self)

            self.table.clear()
            for c in checks:
                self.table.add(c.title, (_STATUS_LABEL.get(c.status, c.status), c.value),
                               tag="muted" if c.status == health.UNKNOWN else None,
                               image=_img(self, f"dot:{_STATUS_COLOR.get(c.status, COL_MUTED)}"))

            adv = self.advice
            adv.configure(state="normal")
            adv.delete("1.0", "end")
            bad = [c for c in checks if c.status in (health.BAD, health.WARN)]
            bad.sort(key=lambda c: 0 if c.status == health.BAD else 1)
            unknown = [c for c in checks if c.status == health.UNKNOWN]
            if not bad:
                adv.insert("end", "Nothing that could be checked needs attention.\n"
                           if unknown else "Nothing needs attention.\n", "h_ok")
            for c in bad:
                adv.insert("end", c.title, "h_" + c.status)
                if c.value:
                    adv.insert("end", f"  \u00b7  {c.value}", "value")
                adv.insert("end", "\n")
                if c.advice:
                    adv.insert("end", f"{c.advice}\n", "body")
                for d in c.detail[:5]:
                    adv.insert("end", f"\u2022  {d}\n", "detail")
                adv.insert("end", "\n")
            adv.configure(state="disabled")

            if unknown:
                n_u = len(unknown)
                text = (f"{n_u} check{'s' if n_u != 1 else ''} could not be read "
                        f"({_join([c.title for c in unknown])}), so "
                        f"{'they are' if n_u != 1 else 'it is'} not counted in the score.")
                action = None
                if not base.is_admin():
                    text += " Some checks can only be read with administrator rights."
                    action = ("Restart as administrator", self.app._elevate)
                self.notice.show(text, action, fill="x", pady=(px(12), 0),
                                 before=self._body)
            else:
                self.notice.hide()

        def error(exc, tb):
            self.run_btn.configure(state="normal")
            self.status.configure(text="failed")
            messagebox.showerror("Health check failed", f"{exc}\n\n{tb[-500:]}")

        self.worker.start(job, None, done, error)

    def snapshot(self) -> None:
        from . import health
        if not self.checks:
            messagebox.showinfo("Sweep", "Run the health check first.")
            return
        health.save_snapshot(self.checks)
        hist = health.load_history()
        self.status.configure(text=f"saved ({len(hist)} snapshot(s))")


# --------------------------------------------------------------------------
# app shell
# --------------------------------------------------------------------------

class SweepApp(tk.Tk):
    # sidebar order; Ctrl+1..9 and Ctrl+0 follow it
    NAV_MAIN = (("clean", "Clean"), ("space", "Space"), ("startup", "Startup"),
                ("health", "Health"))
    NAV_TOOLS = ("Updates", "Applications", "Drivers", "Automatic cleaning",
                 "Secure erase", "Cookie keep-list")

    def __init__(self) -> None:
        enable_dpi_awareness()
        super().__init__()
        global S
        try:
            S = max(1.0, self.winfo_fpixels("1i") / 96.0)
        except tk.TclError:
            S = 1.0
        _init_fonts(self)
        self.title(f"Sweep {__version__}")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w = min(px(1240), int(sw * 0.94))
        h = min(px(800), int(sh * 0.90))
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 3)
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(px(1000), px(620))
        _style(self)
        self._load_imported()
        cfg = config.load()
        self.recycle_var = tk.BooleanVar(value=bool(cfg.get("recycle_bin", False)))
        self.elevate_var = tk.BooleanVar(value=bool(cfg.get("auto_elevate", False)))

        try:
            self._win_icon = tk.PhotoImage(file=ICON_PNG)
            self.iconphoto(True, self._win_icon)
        except Exception:
            self._win_icon = None

        self._build_shell()
        self._bind_keys()
        _dark_title_bar(self)

    # ---- shell ------------------------------------------------------------

    def _build_shell(self) -> None:
        self._statusbar()
        self.sidebar = _Sidebar(self, self)
        self.sidebar.pack(side="left", fill="y")
        tk.Frame(self, bg=COL_LINE, width=1).pack(side="left", fill="y")
        content = ttk.Frame(self)
        content.pack(side="left", fill="both", expand=True)

        self.nb = _Stack(content)
        self.nb.pack(fill="both", expand=True, padx=px(PADX), pady=(0, px(18)))
        self.clean_tab = CleanTab(self.nb, self)
        self.space_tab = SpaceTab(self.nb, self)
        self.startup_tab = StartupTab(self.nb, self)
        self.tools_tab = ToolsTab(self.nb, self)
        self.health_tab = HealthTab(self.nb, self)
        for page in (self.clean_tab, self.space_tab, self.startup_tab,
                     self.tools_tab, self.health_tab):
            self.nb.add(page)

        self._pages = {"clean": self.clean_tab, "space": self.space_tab,
                       "startup": self.startup_tab, "health": self.health_tab}
        self._nav_order: list[str] = []
        for key, text in self.NAV_MAIN:
            self.sidebar.item(key, text, lambda k=key: self.show(k))
            self._nav_order.append(key)
        self.sidebar.heading("Tools")
        for title in self.NAV_TOOLS:
            self.sidebar.item(title, title, lambda t=title: self.show(t))
            self._nav_order.append(title)
        self._sidebar_bottom()

        self.nb.on_change = self._on_page
        self.tools_tab.on_change = self._on_tool
        self._on_page(self.nb.current())

    def _sidebar_bottom(self) -> None:
        bottom = self.sidebar.bottom
        admin = base.is_admin()
        row = tk.Frame(bottom, bg=COL_SIDE)
        row.pack(fill="x", padx=px(22), pady=(0, px(4)))
        tk.Label(row, image=_img(self, f"dot:{COL_GREEN if admin else COL_SUBTLE}"),
                 bg=COL_SIDE).pack(side="left")
        tk.Label(row, text="Administrator" if admin else "Standard user", font=f(9),
                 bg=COL_SIDE, fg=COL_FG if admin else COL_MUTED).pack(side="left",
                                                                     padx=(px(6), 0))
        if not admin:
            link = tk.Label(bottom, text="Restart as administrator", font=f(9),
                            bg=COL_SIDE, fg=COL_ACCENT, cursor="hand2", anchor="w")
            link.pack(fill="x", padx=px(22), pady=(0, px(8)))
            link.bind("<Button-1>", lambda e: self._elevate())
        settings = self.sidebar.item("settings", "Settings", lambda: None, parent=bottom)
        settings.command = lambda: self._show_settings(settings)
        tk.Label(bottom, text="No telemetry \u00b7 no upsell",
                 font=f(8), bg=COL_SIDE, fg=COL_SUBTLE, anchor="w",
                 wraplength=px(190), justify="left").pack(fill="x", padx=px(22),
                                                          pady=(px(10), 0))

    def show(self, key: str) -> None:
        if key in self._pages:
            self.nb.select(self._pages[key])
        elif key in self.tools_tab.panels:
            self.nb.select(self.tools_tab)
            self.tools_tab.select(self.tools_tab.panels[key])
            self._on_tool(self.tools_tab.current())

    def _key_for(self, page) -> str:
        if page is self.tools_tab:
            cur = self.tools_tab.current()
            return getattr(cur, "TITLE", "")
        for k, p in self._pages.items():
            if p is page:
                return k
        return ""

    def _on_page(self, page) -> None:
        self.sidebar.set_active(self._key_for(page))
        self._render_status()
        if page is self.startup_tab and not self.startup_tab.items:
            self.startup_tab.refresh()
        if page is self.health_tab and not self.health_tab.checks:
            self.health_tab.refresh()
        if page is self.tools_tab:
            cur = self.tools_tab.current()
            if cur is not None:
                cur.on_show()
        self.refresh_facts()

    def _on_tool(self, panel) -> None:
        if self.nb.current() is self.tools_tab and panel is not None:
            self.sidebar.set_active(panel.TITLE)
            self._render_status()
            panel.on_show()

    def _bind_keys(self) -> None:
        self.bind_all("<F5>", lambda e: self._refresh_active())
        self.bind_all("<Control-q>", lambda e: self.destroy())
        for i, key in enumerate(self._nav_order[:10]):
            digit = (i + 1) % 10
            self.bind_all(f"<Control-Key-{digit}>", lambda e, k=key: self.show(k))

    def _show_settings(self, anchor: tk.Widget) -> None:
        m = tk.Menu(self, tearoff=0, bg=COL_PANEL, fg=COL_FG, bd=0,
                    activebackground=COL_ACCENT, activeforeground=COL_ON_ACCENT,
                    selectcolor=COL_ACCENT, font=f(10))
        m.add_command(label="Import CCleaner rules\u2026",
                      command=self.clean_tab.import_ccleaner)
        m.add_separator()
        m.add_checkbutton(label="Always start as administrator",
                          variable=self.elevate_var, command=self._toggle_auto_elevate)
        if not base.is_admin():
            m.add_command(label="Restart as administrator now", command=self._elevate)
        m.add_command(label="Create a restore point now",
                      command=self._make_restore_point)
        m.add_separator()
        m.add_command(label="Keyboard shortcuts", command=self._shortcuts)
        m.add_command(label="About Sweep", command=self._about)
        m.add_separator()
        m.add_command(label="Exit", accelerator="Ctrl+Q", command=self.destroy)
        try:
            m.tk_popup(anchor.winfo_rootx() + anchor.winfo_width() - px(8),
                       anchor.winfo_rooty())
        finally:
            m.grab_release()

    def _make_restore_point(self) -> None:
        """Create a System Restore point and report exactly what happened."""
        from . import system
        ok, msg = system.create_restore_point("Sweep: manual restore point")
        self.set_status(msg)
        if ok:
            messagebox.showinfo("System Restore", "Restore point created.\n\n" + msg,
                                parent=self)
        else:
            messagebox.showwarning(
                "System Restore",
                "No restore point was created.\n\n" + msg
                + "\n\nSweep will still clean, but this run will not be undoable.",
                parent=self)

    def _shortcuts(self) -> None:
        lines = []
        for i, key in enumerate(self._nav_order[:10]):
            name = dict(self.NAV_MAIN).get(key, key)
            lines.append(f"Ctrl+{(i + 1) % 10}\t{name}")
        messagebox.showinfo("Keyboard shortcuts",
                            "\n".join(lines) + "\n\nF5\tRefresh the current page"
                            "\nCtrl+Q\tQuit", parent=self)

    def _toggle_auto_elevate(self) -> None:
        want = bool(self.elevate_var.get())
        try:
            config.set_value("auto_elevate", want)
        except OSError as exc:
            messagebox.showerror("Sweep", f"Could not save the setting: {exc}",
                                 parent=self)
            return
        if want and not base.is_admin():
            if messagebox.askyesno(
                    "Start as administrator",
                    "Saved. Sweep will request administrator rights each time it "
                    "starts.\n\nRestart now to apply it?", parent=self):
                self._elevate()
        self.set_status(f"start as administrator: {'on' if want else 'off'}")

    def _load_imported(self) -> None:
        """Pick up a previously imported CCleaner ruleset, if there is one."""
        from . import ccimport
        path = ccimport.default_output()
        if os.path.isfile(path) and not rules.EXTERNAL:
            try:
                rules.load_external(path)
            except (OSError, ValueError):
                pass

    def _toggle_recycle(self) -> None:
        try:
            config.set_value("recycle_bin", bool(self.recycle_var.get()))
        except OSError:
            pass

    def _statusbar(self) -> None:
        # Each page keeps its own last message; the bar shows the one for the page
        # on screen, so a scan finishing elsewhere never reads as this page's news.
        self._page_msgs: dict[str, str] = {}
        self._status_font = tkfont.Font(root=self, font=f(9))
        bar = tk.Frame(self, bg=COL_SIDE)
        bar.pack(side="bottom", fill="x")
        tk.Frame(bar, bg=COL_LINE, height=1).pack(side="top", fill="x")
        row = tk.Frame(bar, bg=COL_SIDE)
        row.pack(fill="x", padx=px(16), pady=px(5))
        self.status_row = row
        self.facts_lbl = tk.Label(row, text=self._facts(), font=f(9), bg=COL_SIDE,
                                  fg=COL_SUBTLE)
        self.facts_lbl.pack(side="right")
        self.status_lbl = tk.Label(row, text="", font=f(9), bg=COL_SIDE, fg=COL_MUTED,
                                   anchor="w")
        self.status_lbl.pack(side="left", fill="x", expand=True)
        row.bind("<Configure>", lambda e: self._render_status())

    def _facts(self) -> str:
        total = len(rules.RULES)
        imported = sum(1 for r in rules.RULES if r.get("imported"))
        parts = [f"{total} rules"]
        if imported:
            parts.append(f"{imported} imported")
        try:
            from . import keep as keepmod
            kept = len(keepmod.KeepList.load().domains)
            if kept:
                parts.append(f"{kept} kept site(s)")
        except Exception:
            pass
        return "   \u00b7   ".join(parts)

    def refresh_facts(self) -> None:
        try:
            self.facts_lbl.configure(text=self._facts())
        except Exception:
            pass

    def set_status(self, text: str, source=None) -> None:
        """Record a message for the page `source` belongs to (default: the page
        on screen) and show it if that page is the one being looked at."""
        text = text[:1].upper() + text[1:] if text else ""
        key = self._status_key(source)
        self._page_msgs[key] = text
        if key == self._current_key():
            self._render_status()

    def _current_key(self) -> str:
        try:
            return self._key_for(self.nb.current())
        except AttributeError:
            return ""

    def _status_key(self, source) -> str:
        w = source
        while w is not None:
            if isinstance(w, _ToolPanel):
                return w.TITLE
            for k, page in getattr(self, "_pages", {}).items():
                if page is w:
                    return k
            w = getattr(w, "master", None)
        return self._current_key()

    def _render_status(self) -> None:
        try:
            text = self._page_msgs.get(self._current_key(), "")
            avail = (self.status_row.winfo_width() - self.facts_lbl.winfo_reqwidth()
                     - px(32))
            font = self._status_font
            if avail > 0 and font.measure(text) > avail:
                while text and font.measure(text + "\u2026") > avail:
                    text = text[:-1]
                text = text.rstrip() + "\u2026"
            self.status_lbl.configure(text=text)
        except (tk.TclError, AttributeError):
            pass

    def set_busy(self, busy: bool) -> None:
        try:
            self.config(cursor="watch" if busy else "")
            self.update_idletasks()
        except tk.TclError:
            pass

    def _refresh_active(self) -> None:
        cur = self.nb.select()
        if cur == str(self.clean_tab):
            self.clean_tab.do_scan()
        elif cur == str(self.space_tab):
            self.space_tab.do_scan()
        elif cur == str(self.startup_tab):
            self.startup_tab.refresh()
        elif cur == str(self.health_tab):
            self.health_tab.refresh()

    def _about(self) -> None:
        total = len(rules.RULES)
        imported = sum(1 for r in rules.RULES if r.get("imported"))
        messagebox.showinfo(
            "About Sweep",
            f"Sweep {__version__}\n\n"
            f"{total} cleaning rules ({imported} imported from CCleaner)\n"
            f"Python {sys.version.split()[0]}  \u00b7  Tk {tk.TkVersion}\n\n"
            "No telemetry, no upsell, no bundled software.\n"
            "Deletions are logged; registry edits are backed up.",
            parent=self)

    def _elevate(self) -> None:
        if not base.IS_WINDOWS:
            return
        if messagebox.askyesno(
                "Restart as administrator",
                "System-wide categories (Windows Update cache, component logs, "
                "Delivery Optimization, WinSxS) need administrator rights.\n\n"
                "Windows Update and driver checks also need elevation.\n\n"
                "Restart Sweep elevated now?", parent=self):
            if base.relaunch_as_admin():
                self.destroy()
            else:
                messagebox.showerror("Sweep", "Elevation was cancelled or refused.",
                                     parent=self)


def _relaunch_elevated_gui() -> bool:
    """Restart this GUI through UAC. Returns True when the parent should exit."""
    if getattr(sys, "frozen", False):
        # Packaged build: there is no interpreter or module to re-invoke, so
        # relaunch the executable itself. Dropping -m sweep is essential.
        return base.relaunch_elevated(
            "--elevated", cwd=os.path.dirname(sys.executable), exe=sys.executable)

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # prefer pythonw so the elevated instance has no console window
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.isfile(pyw):
        exe = pyw
    return base.relaunch_elevated("-m sweep gui --elevated", cwd=root, exe=exe)


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    already_tried = "--elevated" in argv

    # Elevate before building any window so the user sees one UAC prompt and one
    # window, not a window that then restarts itself.
    if not already_tried and not base.is_admin():
        try:
            if config.load().get("auto_elevate"):
                if _relaunch_elevated_gui():
                    return
        except Exception:
            pass

    app = SweepApp()
    app.mainloop()


if __name__ == "__main__":
    main()
