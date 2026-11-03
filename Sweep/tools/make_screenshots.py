"""Capture screenshots of the Sweep GUI for documentation."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PIL import ImageGrab

import sweep.gui as gui
from sweep import rules

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
os.makedirs(OUT, exist_ok=True)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_imported = os.path.join(HERE, "logs", "imported-rules.json")
if os.path.isfile(_imported):
    print(f"loaded {rules.load_external(_imported)} imported rule(s)")


def pump(app, seconds):
    end = time.time() + seconds
    while time.time() < end:
        app.update_idletasks()
        app.update()
        time.sleep(0.02)


def wait_worker(app, worker, timeout=120):
    end = time.time() + timeout
    while worker.busy and time.time() < end:
        app.update_idletasks()
        app.update()
        time.sleep(0.05)
    pump(app, 0.6)


def grab(app, name):
    app.deiconify()
    app.attributes("-topmost", True)
    app.lift()
    app.focus_force()
    app.update_idletasks()
    app.update()
    pump(app, 0.8)
    x, y = app.winfo_rootx(), app.winfo_rooty()
    w, h = app.winfo_width(), app.winfo_height()
    img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
    path = os.path.join(OUT, name)
    img.save(path)
    print("saved", path, img.size)


app = gui.SweepApp()
pump(app, 0.8)

# --- Clean tab: run a real scan -----------------------------------------
app.clean_tab.selected = set(rules.ids())      # built-in + imported, for the demo
app.clean_tab._populate()
app.clean_tab.do_scan()
wait_worker(app, app.clean_tab.worker, timeout=300)
# collapse to the group rollups so the image shows coverage, not a wall of rows
for gid in app.clean_tab.group_items.values():
    try:
        app.clean_tab.tree.item(gid, open=False)
    except Exception:
        pass
app.clean_tab.tree.yview_moveto(0)
grab(app, "clean.png")

# --- Space tab: scan the user profile ------------------------------------
app.nb.select(app.space_tab)
pump(app, 0.4)
app.space_tab.path.set(os.environ.get("USERPROFILE", "C:\\"))
app.space_tab.do_scan()
wait_worker(app, app.space_tab.worker, timeout=180)
grab(app, "space.png")

# --- Startup tab ---------------------------------------------------------
app.nb.select(app.startup_tab)
pump(app, 0.3)
app.startup_tab.refresh()
wait_worker(app, app.startup_tab.worker, timeout=120)
grab(app, "startup.png")

# --- Tools tab (Applications panel) --------------------------------------
app.nb.select(app.tools_tab)
app.tools_tab.select(1)                    # Applications
pump(app, 0.4)
panel = app.tools_tab.nametowidget(app.tools_tab.tabs()[1])
panel.list_apps()
pump(app, 0.3)
wait_worker(app, panel.worker, timeout=180)
pump(app, 0.4)
grab(app, "tools.png")

# --- Tools tab (Drivers panel) -------------------------------------------
app.tools_tab.select(2)                    # Drivers
pump(app, 0.4)
dp = app.tools_tab.nametowidget(app.tools_tab.tabs()[2])
dp.inventory()
pump(app, 0.3)
wait_worker(app, dp.worker, timeout=180)
pump(app, 0.4)
grab(app, "drivers.png")

# --- Health tab ----------------------------------------------------------
app.nb.select(app.health_tab)
pump(app, 0.3)
app.health_tab.refresh()
wait_worker(app, app.health_tab.worker, timeout=300)
grab(app, "health.png")

app.destroy()
print("done")
