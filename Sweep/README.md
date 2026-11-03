# Sweep

A Windows cleaner that **shows its work**, never nags, and does not phone home.

Built as an independent replacement for CCleaner 7 after reverse-engineering what
that product actually does under the hood — and after confirming that most of its
remaining value sits behind a subscription. Sweep covers the same ground, adds the
things CCleaner does not do, and refuses to do the things CCleaner should not.

```
sweep scan                     # measure, change nothing
sweep clean --apply            # actually delete
sweep analyze C:\ --duplicates # find what is really eating the disk
sweep startup                  # see and toggle startup programs
Sweep-GUI.pyw                  # graphical interface
```

Requires Windows 10/11 and Python 3.9+. No third-party packages — everything is
standard library (`tkinter`, `ctypes`, `winreg`, `sqlite3`).

Screenshots: [`docs/clean.png`](docs/clean.png) ·
[`docs/space.png`](docs/space.png) · [`docs/startup.png`](docs/startup.png) ·
[`docs/tools.png`](docs/tools.png) · [`docs/drivers.png`](docs/drivers.png) ·
[`docs/health.png`](docs/health.png).
What CCleaner 7 actually does, and what was learned from it:
[`docs/ccleaner-analysis.md`](docs/ccleaner-analysis.md).

---

## Why this exists

CCleaner 7 ships its cleaning logic as a **plain-text rules file**
(`ccleaner.ini`, 769 sections, ~3,000 file rules) driven by a native engine and a
WebView2 front end. Reading that file establishes precisely what it cleans. Two
observations followed:

1. A large share of the useful work is *just* enumerated cache directories.
2. The differences that matter to a buyer are not the cleaning — they are the
   upsell, the telemetry, and the features held back for subscribers.

Sweep reimplements the cleaning from scratch and gives away what is paywalled.
It shares no code, data or rules with CCleaner; the ruleset here was written
against Microsoft and application documentation and then validated against real
directories on a live machine.

---

## The safety model

Most cleaners are one bad wildcard away from an incident. Sweep is built around a
contract that the test suite enforces:

| Property | How it is guaranteed |
|---|---|
| Nothing is deleted without an explicit act | `clean` is a dry run unless `--apply`; the GUI requires a confirmation dialog |
| Only previewed files can be deleted | The scanner produces an allow-list of exact paths; the cleaner refuses any path not in it (`test_path_outside_allowlist_is_refused`) |
| Junctions and symlinks are never followed | A directory junction inside a cache cannot widen a rule into `System32` (`test_junction_is_not_followed`) |
| User data is never matched | No rule targets a profile root; a test asserts this (`test_no_rule_targets_whole_profile`) |
| Risky actions are never implicit | Anything `caution`-level is off by default and asserted so (`test_caution_is_never_default`) |
| In-use files are skipped, not forced | Locked files are counted and reported; the run continues |
| Every deletion is recorded | Append-only JSONL audit log in `%LOCALAPPDATA%\Sweep\logs\` |
| Deletion can be recoverable | "Send to Recycle Bin" toggle in the GUI, `--recycle` in the CLI |

A hardened name list (`pagefile.sys`, `ntuser.dat`, registry hives, …) is refused
outright regardless of rule, and files are only ever removed as individual files —
never a recursive directory wipe.

---

## Coverage: two tiers

Sweep has **48 built-in rules** and can additionally **import CCleaner's own
ruleset** from your machine, reaching **761 of its 768 categories**.

| Tier | Categories | Source | On by default |
|---|---|---|---|
| Built-in | 48 | authored here, curated | yes (safe/moderate) |
| Imported | 761 | your local `ccleaner.ini`, parsed at runtime | **no** |

### Importing CCleaner's rules

CCleaner ships its cleaning logic as a plain-text file. Sweep reads *your* copy
and executes those rules through its own engine — nothing is copied into this
repository or redistributed, and the file never leaves the machine that already
has a licence to it.

```
sweep import                                  # auto-detect the install
sweep import --from "C:\Program Files\Piriform\CCleaner 7\ccleaner.ini"
sweep scan  --imported                        # scan only imported categories
sweep scan  --rules-file <path> --all         # built-in + imported
```

On the machine this was built on the import reported:

```
categories        768 found, 761 imported
file rules        3,050
registry rules    1,163
system actions    65
unsafe dropped    0
```

Of 768, **761 import and 7 do not** — and the 7 are named rather than silently
ignored (`Registry - Installers`, `- Firewall Rules`, `- Interface`,
`- Windows Services`, `- Help Files`, `- Invalid File Extensions`,
`- Browser Helper`). Sweep will not pretend to clean what it cannot verify.

Every imported rule is still re-validated first. Two things happen:

* structurally dangerous targets are dropped — a drive root, a swept profile
  root, a recursive unbounded sweep of `C:\Windows`, or a system directory
  matched with `*.dll`/`*.exe`;
* anything matching cookie/history/password/session/form/MRU is forced to
  `caution` and forced **off**, even if the source file marks it as a default.

Imported rules are never selected by default. You opt in.

### Measured on a real machine

| Rule set | Reclaimable | Files |
|---|---|---|
| Built-in only | 3.8 GB | 42,400 |
| CCleaner rules imported | **7.6 GB** | 36,276 |

The imported set more than doubled the total because it covers things a curator
forgets: 2.5 GB of ChatGPT/Codex cache, 918 MB of Codex history, plus Claude and
Cursor caches. That is the honest argument for importing rather than
re-authoring — and also the argument for shipping both.

### Built-in rules by group

**Windows** — temp files, thumbnail/icon cache, GPU shader caches, error-reporting
queue and crash dumps, kernel dumps, Windows Update download cache, Delivery
Optimization, CBS/DISM/update logs, setup caches, chkdsk fragments, Defender scan
history. Optional and off by default: installer patch cache, Prefetch, font cache,
the previous Windows installation, Recycle Bin, and DISM component-store cleanup.

**Browsers** — Chrome, Edge, Brave, Vivaldi, Chromium, Firefox, Opera. Cache,
code cache, GPU cache, shader cache and service-worker caches only. History and
cookies exist as separate `caution` rules that are never selected by default,
because deleting them is a privacy decision rather than a space cleanup.

**Developer** — pip, npm, Yarn, pnpm, NuGet, Cargo, Go, Gradle, VS Code/Cursor/
Windsurf, JetBrains, Visual Studio. On a modern machine this is usually where the
gigabytes are, and it is a category most cleaners handle badly.

**Apps** — Teams, Slack, Discord, Spotify, Steam shader cache, OneDrive logs,
Zoom, Office document cache.

**Privacy** — history and cookies, off by default.

### System actions

13 clean actions are implemented and mapped from the imported rules:

`empty_recycle_bin` · `flush_dns` · `dism_component_cleanup` ·
`clean_volumecache:<handler>` (drives Windows' own Disk Cleanup handlers) ·
`clear_clipboard` · `clear_recent_docs` · `clear_jump_lists` ·
`clear_event_logs` · `clean_environment_path` · `clear_office_mru` ·
`clear_last_visited` · `clear_credentials` · `clear_network_passwords` ·
`remove_empty_directories`

### Registry cleaning

This is the most discredited part of any cleaner, so Sweep implements a narrow
version: it removes an entry only when it can **prove** the entry is dangling —
the file it names no longer exists, or the program is no longer installed.

Implemented, verifiable categories:

| Category | What is proven |
|---|---|
| `muicache` | cached display name for a binary that is gone |
| `app_paths` | registered `App Paths` executable missing |
| `shared_dlls` | `SharedDLLs` path absent (reference counts untouched) |
| `open_with` | `OpenWithList` handler missing |
| `obsolete_software` | uninstall entry whose install location and uninstaller are both gone |
| `run_at_startup` | `Run` value whose executable no longer exists |
| `sound_events` | sound scheme pointing at a missing `.wav` |
| `fonts` | installed-font entry whose font file is missing |

Everything removed is written to a JSON backup **first**, and the clean is
abandoned if the backup cannot be written — registry edits are the one thing that
must never be irreversible. Replay with:

```
sweep restore-registry %LOCALAPPDATA%\Sweep\logs\registry-backups\<file>.json
```

Deliberately **not** implemented, with the reason surfaced in the tool:
firewall rules (needs the COM API), service records (can stop a driver loading),
MSI product records (breaks repair/uninstall), and the categories with no
verifiable definition of "dangling".

### What it deliberately will not do

* **No "registry cleaning" in the usual sense.** Only provably dangling entries
  are removed, always behind a mandatory backup. Sweep does not delete entries
  merely because they look old, unused, or unfamiliar — that is where cleaners
  earn their reputation for breaking applications.
* **No "driver updater".** Silently swapping drivers is how machines break.
* **No bundled browser, no "PC health" score, no upsell, no telemetry.**
* **No touching of Firefox/Thunderbird profile bodies** — `logins.json`,
  `key4.db` and `places.sqlite` hold credentials, bookmarks and history.

---

## Beyond cleaning

**Space tab / `sweep analyze`** — a squarified treemap of any folder, click to
drill in, plus the largest files and (on request) duplicate detection by
size → 64 KiB prefix hash → full hash. On the machine this was built on it
immediately surfaced 49.8 GB under `AppData`, a 7.3 GB VM disk image and 4 GB of
model weights a cleaner would never mention. CCleaner has no equivalent.

**Startup tab / `sweep startup`** — the feature CCleaner sells as *Performance
Optimizer*. Lists Run/RunOnce entries, Startup-folder items, scheduled tasks and
optionally auto-start services. Disabling is **reversible**: registry entries are
moved into a Sweep-owned quarantine store and restored on re-enable; folder items
are moved, never deleted.

**System facts** — reports `hiberfil.sys`, `pagefile.sys`, `MEMORY.DMP` sizes and
prints the exact command to change them, rather than silently reconfiguring your
machine.

---

## The other modules

Everything CCleaner ships as a separate feature, so nothing is left out:

| Module | Command | GUI |
|---|---|---|
| Laptop health | `sweep health` | Health |
| Unified updates | `sweep update` | Tools → Updates |
| Automatic cleaning | `sweep schedule` | Tools → Automatic cleaning |
| Uninstaller + leftovers | `sweep apps` | Tools → Applications |
| Driver inventory + updates | `sweep drivers` | Tools → Drivers |
| Software updates | `sweep updates` | Tools → Updates |
| Secure erase | `sweep secure` | Tools → Secure erase |
| Cookie keep-list | `sweep keep` | Tools → Cookie keep-list |
| Disk usage treemap | `sweep analyze` | Space |
| Startup manager | `sweep startup` | Startup |

### Unified updates — `sweep update`

One preview across all three update sources, then one confirmation:

```
sweep update                 # preview software + Windows + drivers
sweep update --apply         # install everything shown
sweep update --elevate       # relaunch elevated first (Windows/drivers need it)
sweep update --no-drivers    # narrow the scope
sweep windows-update --apply # Windows Update only
```

| Source | Mechanism | Covers | Admin |
|---|---|---|---|
| Software | winget | apps in the winget repository | no |
| Windows | Windows Update COM | Windows quality/feature updates | **yes** |
| Drivers | Windows Update COM | drivers Microsoft publishes for your hardware IDs | **yes** |

Nothing installs without the preview, each update's result code is printed
(`2 = succeeded`, `4 = failed`), and a required restart is reported rather than
silently pending. Elevation is a genuine relaunch: `--elevate` starts a new
elevated instance with the same arguments and exits the original.

Driver coverage is honestly limited — on a vendor laptop, GPU and chipset drivers
usually ship through the OEM's own tool, not Windows Update. Sweep reports what
Windows Update offers and does not pretend to know about anything else.

### Automatic cleaning — `sweep schedule`

Registers one Task Scheduler job, `Sweep - Automatic Clean`, that runs
`pythonw -m sweep clean --apply --quiet` so no console ever appears.

```
sweep schedule --frequency weekly --at 12:00 --days MON,WED,FRI
sweep schedule --status
sweep schedule --remove
```

Driven through the Schedule.Service COM API rather than `schtasks.exe`, which is
missing or blocked on some systems. Removal leaves no residue.

### Uninstaller and leftovers — `sweep apps`

Reads all three Uninstall roots (HKLM 64-bit, HKLM 32-bit, HKCU) and reports real
on-disk size from `InstallLocation`. Three details matter:

* Windows Installer patch entries (`ParentKeyName`) and `SystemComponent=1`
  records are excluded, so the list shows programs, not updates;
* **Sweep never deletes an install folder.** It runs the vendor's own uninstaller;
* leftover detection is **advisory** — it lists folders and registry keys whose
  name matches, and says "evidence, not proof".

### Drivers — `sweep drivers`

`--check` asks **Windows Update** for driver-class updates and `--install` applies
them. No third-party driver catalogue is bundled and nothing is fetched from an
unvetted mirror: these are signed packages matched to your hardware, and
Device Manager can roll them back.

Inventory falls back to the driver registry when `driverquery` is unavailable —
it reports "version mismatch" on some builds, which is exactly why the fallback
exists.

### Software updates — `sweep updates`

Uses **winget**, so "outdated" means the package manager's signed catalogue, not
a scraped version list. `--apply all` or `--apply <id>`.

### Secure erase — `sweep secure`

Overwrite then delete, 1 or 3 passes (zeros → ones → random), plus `--free-space`
which fills the volume with random data and removes it.

Stated plainly in the tool and here: **on an SSD with wear levelling this cannot
guarantee the original cells are erased.** Only BitLocker key destruction or the
drive's own ATA Secure Erase achieves that. A software cleaner that promises
otherwise is overselling.

### Cookie keep-list — `sweep keep`

```
sweep keep --add github.com --add google.com
```

When the Privacy cookie rule runs, Sweep does **not** delete the cookie database.
It rewrites it: rows whose host matches the keep-list survive, everything else is
removed, and the database is backed up first. Works for Chromium's `cookies`
table and Firefox's `moz_cookies`. An empty keep-list is refused rather than
silently removing every cookie.

---

### Laptop health — `sweep health`

A cleaner reclaims space; this answers whether anything is *degrading*. Twelve
checks, a 0-100 score, and a JSONL history so you can see a trend rather than a
snapshot.

| Check | Source | Why it matters |
|---|---|---|
| Free space | `shutil.disk_usage` | below 8% breaks Windows Update and the page file, and SSD write amplification rises sharply |
| Uptime | `GetTickCount64` | long uptimes hide pending-update reboots and slow leaks |
| Pending reboot | registry markers | updates are half-applied until you restart |
| Battery | `GetSystemPowerStatus` | level and AC state |
| TRIM | `fsutil` | off = accelerated SSD wear and slower writes |
| Stability | event log 41/6008/1001/7/51/153/55 | unexpected shutdowns and storage retries |
| Power plan | `powercfg` | a max-performance plan on a laptop means heat and short battery life |
| Sleep/hibernate | registry | fast startup makes "shutdown" a partial hibernate |
| Secure Boot | registry | blocks bootkits |
| Defender | policy registry, then WMI | real-time protection actually on |
| Startup programs | Run keys | every login pays for them |
| Watchdog | Task Scheduler | is automatic cleaning actually scheduled |

Two things learned while building this, both now handled:

* **One crash is logged several times.** Kernel-Power 41, EventLog 6008 and
  BugCheck 1001 fire within seconds of each other. Counting rows reported 6
  unexpected shutdowns where there were **2**. Events closer than 10 minutes are
  now grouped into one incident.
* **Most of Windows' health surface needs elevation.** CIM/WMI, `powercfg
  /batteryreport` and `Get-StorageReliabilityCounter` are all refused to a
  standard user. Every check therefore has a non-elevated path, and reports
  `unknown` rather than a false green tick.

---

## What I would add next, and what I would not

Ranked by actual benefit to a laptop, not by how good it sounds in a feature list.

**Worth building**

1. **An elevated health pass.** Design capacity vs current full charge (battery
   wear %), SSD SMART wear and power-on hours, `DISM /ScanHealth`, `sfc /scannow`
   and `powercfg /sleepstudy`. This is the single biggest gap — the data exists
   but needs admin. The fix is a "Restart as admin → full report" flow.
2. **Health watchdog with alerting.** The scheduler already runs cleaning; it
   should also snapshot health and *tell you* when the score drops or a check
   flips to bad. The history file already exists.
3. **Restore point before any clean.** One `Checkpoint-Computer` call turns a
   regretted clean into an undo. Cheap, high value.
4. **Backup verification.** Most people find out their backup was not running
   when they need it. Check File History / OneDrive / System Restore is enabled
   *and* that a recent restore point or backup actually exists.
5. **Windows Update orchestration.** Detect, list, and install pending updates
   through the Update COM API.

**Not worth building — and why**

* **SSD defragmentation.** Harmful. It burns write cycles for zero gain. Any
  tool offering "optimize your SSD" by defragmenting is doing damage. (TRIM, which
  Sweep checks, is the correct SSD maintenance.)
* **"RAM boosters".** Freeing standby memory makes Windows slower, not faster.
* **Registry cleaning for speed.** Already implemented only where it removes
  provably dangling entries, and it is not a speed feature.
* **Driver boosters.** Driver churn is a leading cause of new breakage; only
  hardware-matched, signed updates from Windows Update are worth applying.
* **Temperature/fan tweaking.** Needs vendor-specific EC access and varies per
  model; the failure mode is a hot laptop with a stuck fan.

Being precise about this, because it matters:

---

## What is verified, and what is not

Being precise about this, because it matters:

**Verified by the test suite (120 tests).** Allow-list enforcement, junction
avoidance, dry-run safety, caution-never-default, rule-variable expansion, the
dangerous-target validator, registry backup → remove → restore with type
preservation, cookie filtering for both browser layouts, secure erase, winget
output parsing, driver inventory, the scheduler's launcher and weekday logic,
health scoring bands, crash-incident grouping (so one shutdown is not counted three
times), the checkbox selection model, parallel-vs-serial scan equivalence, and that
every Tools panel actually puts its content on screen (a panel that builds a
widget but never packs it renders as an empty tab).

**Verified manually on this machine.** 761/768 category import; 12.1 GB /
78,892 files scanned across 809 rules; full application inventory with sizes;
416 kernel drivers via the registry fallback; a live health report that
correctly surfaced 2 unexpected shutdowns, a queued reboot, and a 20-day uptime.

**Not verified here.** Scheduling, winget, and every Windows Update path
(`sweep update`, `sweep windows-update`, `sweep drivers --check/--install`) were
blocked by the confinement this was built under: Task Scheduler COM and
`schtasks` both refused, `winget` is a 0-byte App Execution Alias returning
`0x8A150001`, and Windows Update `Search()` returns *Access denied* to a
standard user.

They are implemented with explicit, specific error paths — the winget failure
names the HRESULT, the Windows Update failure names elevation as the fix — but
their happy path has not been exercised. Run each once yourself:

```
sweep update --elevate
sweep windows-update
sweep schedule --status
```

If any misbehaves, the exact error is what I need to fix it against.

---

## Interface

The GUI is tkinter, deliberately — zero dependencies, starts instantly, and works
on a machine with no runtime installed. What it does have:

* **Per-monitor DPI awareness.** Without `SetProcessDpiAwareness`, Windows
  bitmap-stretches the window on a HiDPI screen: blurry text and a Tk coordinate
  system that disagrees with the mouse. Every dimension goes through a single
  `px()` scale factor instead of magic numbers.
* **An app icon**, generated by `tools/make_icon.py` and applied via
  `iconphoto`.
* **A sidebar** instead of nested tabs: Clean, Space, Startup and Health, then
  every tool as its own page. Admin status, *Restart as administrator* and a
  Settings menu (import rules, always start as administrator, About) sit at
  the bottom of it.
* **One dark theme everywhere** — tables, scrollbars, checkboxes, inputs and,
  on Windows 10/11, the title bar. Every page has the same shape: a title with
  a one-line explanation, its controls, then its content in a card.
* **A persistent status bar** showing the last action on the left and live facts
  on the right: rule count, how many were imported, how many domains are in the
  keep-list.
* **Alternating row striping** so wide tables stay readable, applied as a
  background-only tag so risk/status foreground colours still work.
* **Keyboard**: `F5` refresh the current page, `Ctrl+1..9` and `Ctrl+0` jump
  to sidebar pages in order, `Ctrl+Q` quit.
* **A busy cursor** during any background job, wired once in the worker rather
  than in every handler.
* One accent button per pane; everything else is a neutral secondary action.

### Picking and choosing

Updates, driver updates and applications are **real tables, not a wall of text**.
Update lists carry a checkbox per row — click anywhere on a row to toggle it —
with `All` / `None` buttons and a live "N selected" counter. Nothing installs
unless you ticked it, and `Install selected` stays disabled until you do.

Driver updates live in their own tab beside the installed-driver inventory, so
"what do I have" and "what is offered" never mix. Applications fill in
progressively — names appear immediately and each size is measured in the
background, so a 70-app list with directory sizes never freezes the window.

### Responsiveness

Two separate problems were fixed here, and only one of them was about cores:

**It froze because the UI thread was doing the work.** Every Tools action used to
run inside the button handler, so Tk stopped repainting until it finished. All of
them now go through the same background `Worker` the Clean tab already used, and
in the smoke test every panel reports the progress bar mapped *and moving* while
it works.

**Then it was made genuinely parallel.** Rules are independent I/O jobs, so the
scanner runs them on a bounded thread pool (default `min(8, CPU count)`).
Measured over ten cache rules on this machine:

```
serial    3,329,770,406 bytes   41,946 files   1.99s
parallel  3,329,770,406 bytes   41,946 files   0.43s   (4.6x)
```

Results are merged in rule order, so output is byte-identical to a serial run —
there is a test asserting exactly that, because a faster scan that returns
different numbers would be worse than a slow one.

Every panel now shows a **progress bar with a percentage** where the total is
knowable (installs, wipes) and an indeterminate bar where it is not (queries),
plus a **live elapsed timer** so a long operation is visibly alive.

### Update failures are explained, not dumped

winget's failures are terse and truncated in a table. Sweep keeps the cell short
(`failed: network`, `failed: wrong installer type`, `failed: app running`,
`failed: needs admin`) and puts the full explanation underneath, so clicking a
row tells you what to actually do. Recognised conditions include
`0x80072ee7` (cannot reach the download source), "install technology is
different" (winget will not replace an app installed by another installer type),
`0x80073d02` (app still running), and a bad installer hash. Failed rows stay
ticked so a retry is one click; successful rows untick themselves and go green.

## Starting elevated

Most of what makes Sweep useful on a laptop — Windows Update, driver checks,
Defender status, battery wear, WinSxS, the Windows Update cache — needs
administrator rights. There are two independent mechanisms, because one alone
leaves a hole:

**1. The shortcut carries the Windows "Run as administrator" flag**
(`SLDF_RUNAS_USER`, `0x2000`). Windows shows the UAC prompt and the shield icon
*before* Python starts, so there is no window flash and no restart. This is set
on the `.lnk` via the `IShellLinkDataList` COM interface.

**2. The app elevates itself when it is not started from the shortcut.**
`config.json` holds `auto_elevate`; when true, `gui.main()` requests elevation
before building any window, relaunching through `pythonw.exe` so the elevated
instance has no console either. A `--elevated` marker is passed to the child so
it never tries again — no UAC loop.

If the user declines the prompt, the app still opens and simply reports the
admin-scoped checks as `unknown` instead of failing.

Toggle it in **File → Always start as administrator**; the setting persists in
`%LOCALAPPDATA%\Sweep\config.json`. Configuration writes merge rather than
replace, so changing one preference never resets another (there is a test for
exactly that).

## Admin rights

Without elevation, user-scoped rules work fully and system-scoped rules report
`needs admin` (and count any denied paths). The GUI offers *Restart as admin*.
Elevation unlocks the Windows Update cache, component logs, Delivery Optimization,
WinSxS cleanup and the other machine-wide categories.

---

## Adding a rule

Rules are plain data in `sweep/rules.py`:

```python
add({
    "id": "app.example",
    "name": "Example cache",
    "group": "Apps",
    "risk": "safe",              # safe | moderate | caution
    "default": True,
    "why": "One line explaining what is lost and why it is safe.",
    "needs_admin": False,
    "procs": ["example.exe"],    # advisory: close it first
    "files": [_f("%LOCALAPPDATA%\\Example\\Cache")],
})
```

`_f(path, pattern="*", recurse=True, remove_empty=False)` accepts `%VARS%` and
wildcard *directory* segments (`%LOCALAPPDATA%\Vendor\User Data\*\Cache`), which
are expanded as directories only.

---

## Tests

```
python -m unittest discover -s tests -v
```

46 tests across two suites. `test_sweep.py` creates a real cache directory next to
a real "precious" document and verifies that cleaning removes the former, spares
the latter, refuses an injected out-of-allow-list path, respects `--min-age`, does
not descend junctions, and that `caution` rules are never defaults.
`test_import.py` covers rule-variable expansion, the drop-dangerous-targets
validator (including that `%WINDIR%|*.old;*.tmp` is allowed while
`%WINDIR%\System32|*.dll` is not), action mapping, and a registry
backup → remove → restore round-trip that checks a DWORD survives with its type
and value intact. Four registry tests skip themselves where the host denies
registry writes.

`test_tools.py` adds coverage for secure erase (including that the wipe payload
is really written and the file really disappears), cookie filtering against
synthetic Chromium *and* Firefox databases, winget table parsing, driver
inventory, and the scheduler's launcher/weekday logic.

---

## Building a standalone executable

Running from source needs Python on `PATH`. To produce a binary that needs
nothing installed:

```
pip install pyinstaller
python -m PyInstaller --noconfirm --clean --onedir --windowed --name Sweep ^
  --icon docs\sweep.ico --add-data "docs\icon.png;docs" --paths . ^
  tools\pyinstaller_entry.py
```

Output is `dist\Sweep\` — a 2.4 MB `Sweep.exe` plus its runtime, about 30 MB in
total and ~995 files. Keep the whole folder together; the `.exe` will not run
without its neighbours.

Notes that matter if you change this:

* **`--onedir`, not `--onefile`.** One-file builds re-extract to `%TEMP%` on
  every launch, costing a few seconds and triggering an antivirus scan each
  time. Only the launcher and its folder need copying.
* **`--windowed`** means no console. A crash produces no visible output, so
  build with `--console` instead when diagnosing a startup failure.
* **`--add-data "docs\icon.png;docs"`** is what keeps the in-window logo; the
  GUI resolves it relative to the package root, which is the extraction root
  when frozen.
* `Sweep.spec` is committed, so `pyinstaller Sweep.spec` reproduces the build
  without retyping the flags.
* `build/` and `dist/` are gitignored — the binary is a release artefact, not
  source.

---

## Limitations — stated plainly

* Rule coverage is curated, not exhaustive. Vendor-specific caches that are not
  listed are simply not cleaned; add a rule.
* Sizes are logical file sizes, not allocated size — sparse and compressed files
  can make the reclaimable figure differ from the space the volume reports.
* Some Windows categories need elevation; the tool reports this rather than
  failing silently.
* The GUI uses tkinter, so it looks like a native-ish Windows app rather than the
  WebView2 surface CCleaner uses. That is a deliberate trade for zero dependencies.
* `sweep analyze --duplicates` reads file contents and is I/O bound; on a large
  volume it is slow by nature.
