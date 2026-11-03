# What CCleaner 7 actually is

Notes from inspecting a retail installation of **CCleaner 7.13.1573.0**
(`C:\Program Files\Piriform\CCleaner 7`, Gen Digital Inc., PE32+ x64, 7.6 MB).

These notes exist to justify the design of Sweep. No CCleaner code, data or rule
text was copied into this project.

---

## Architecture

| Component | Role |
|---|---|
| `CCleaner.exe` | Native C++ x64 front controller |
| `CCleaner_service.exe` | 33 MB privileged helper (system-scope cleaning, updates) |
| `CCleanerDU.dll` (16.7 MB) | Driver Updater engine |
| `CCleanerReactivator.exe` | Subscription/activation broker |
| `gui/` | **WebView2** UI: `index.js`, `frame.js`, ~14 MB of bundled chunks |
| `ccleaner.ini` (495 KB) | **The cleaning ruleset, in plain text** |
| `data/*.db` | SQLite: `CCleanerPO.db`, `CCleanerPOCache.db`, `statistics.db` |
| `data/config.ini` | Remote-config ("Shepherd") flags, A/B test ID, TTL |
| `CCleaner.lic` | Encrypted entitlement blob |
| `wa_*.dll` / `libwa*.dll` | WebView2 loader + "Wa" framework components |

The important observation: **the UI is a web app**, and **the cleaning logic is
data, not code**. That means the product's behaviour is almost entirely
enumerable without touching the native engine.

---

## The rule DSL

`ccleaner.ini` contains **769 sections** and ~3,000 file rules. Each section is
one user-visible category. The grammar is small:

```ini
[Category Name]           ; display name of the category
Author=CCleaner
ID=windows.tempfiles      ; stable identifier
Default=True              ; off / on / true / false
Risk=...                  ; optional
DetectOS=6.0              ; minimum Windows version
DetectFile=...            ; only show if this path exists
ActiveProcesses=chrome.exe  ; offered as "close these first"
Tags=Microsoft,System,TempFiles
WarningRef=3213           ; localised warning text id

FileKey1=%windir%\TEMP|*|RECURSE   ; <path>|<pattern>|<flags>
RegKey1=HKCU\Software\...|ValueName
Action1=DiskCleanup|Thumbnail Cache
OnFile1=*|FileDelete                ; what to do with a matched file
ExcludeKey1=...
MaxProcessStopTimeout=...
```

Measured key frequency across the whole file:

| Key type | Count |
|---|---|
| `FileKey` | 3,048 |
| `RegKey` | 1,167 |
| `OnFile` | 641 |
| `DetectFile` | 528 |
| `Detect` | 449 |
| `ActiveProcesses` | 261 |
| `WarningRef` | 87 |
| `Action` | 72 |
| `ExcludeKey` | 56 |

Only **two** behavioural flags exist across all 3,000+ file rules:
`RECURSE` (1,353 uses) and `REMOVESELF` (67). Patterns may hold several masks
separated by `;`, and paths may contain `%VARS%`.

The entire `Action` vocabulary is **14 handlers**:

```
CommonLastVisited   Registry          DiskCleanup        CleanOfficeMRU
CleanCredentials    RemoveEmptyDirectories                EmptyRecycleBin
ShellAddToRecentDocs CleanClipboard   CleanDNSCache      CleanWindowsEventLogs
CleanEnvironmentPath TaskbarJumpLists CleanNetworkPasswords
```

`DiskCleanup|<name>` (12 uses) is the interesting one: it delegates to Windows'
own **VolumeCaches** COM handlers rather than reimplementing cleanup. The
registry at
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches`
enumerates 32 handlers on a current build, including `Update Cleanup`,
`Previous Installations`, `Windows ESD installation files`,
`Delivery Optimization Files` and `Device Driver Packages` — which is where the
largest legitimate wins live. Sweep takes the same route for `WinSxS` (via DISM)
and the Recycle Bin (via `SHFileOperationW`).

### Consequence for Sweep

Because the rule format is trivial and the categories are just directory
patterns, an independent implementation is straightforward — and can be
*stricter*. Two things stood out while reading it that Sweep deliberately does
differently:

* the browser categories match whole `User Data` trees for some legacy browsers,
  which includes credential and history stores;
* the registry categories are extensive, and registry cleaning is not a space
  optimisation.

---

## Licensing and gating

`gui/chunks/tierService.js` is the entitlement layer. Features carry
`premium` / `edition` / `visible` properties fetched from the backend, and
subscription state is one of:

```
subscription_free   subscription_free_expired
subscription_paid   subscription_paid_expired
subscription_trial  subscription_trial_expired
```

`isTrial()` accepts `trial` / `offline_trial`; `showUpsells()` keys off the
remaining licence days. The feature matrix is **server-driven**
(`data/config.ini` points at a remote config with a `ConfigId`, `TTL` and
`NextUpdate`), so the gated set can change without shipping a new build.

`CCleaner.lic` is an encrypted entitlement blob (a GUID is visible at the tail);
it is not a plaintext key file.

> **Scope note.** Sweep does not touch this. Circumventing the licence check
> would be a licence violation and a DRM-avoidance problem, and it also would not
> produce a better cleaner. The response to "the useful parts are paywalled" is to
> write a better cleaner, which is what this repository is.

---

## Telemetry and configuration

`data/usercfg.ini` on this install contained an `[Analytics]` block with
`lastDeviceDetails` and `lastHeartbeat` timestamps, and `[GDPR]
thirdPartyAnalyticsEnabled=1`. `data/settings.json` exposed
`analytics_enabled`, `offer_1st_party_products`, `offer_3rd_party_products`,
`staging_servers`. Sweep has no analytics at all; there is nothing to opt out of.

---

## What Sweep took from this

1. **Categories are data.** Sweep has a declarative ruleset
   (`sweep/rules.py`) rather than hard-coded cleaning logic.
2. **Delegation beats reimplementation** for anything Windows already does
   correctly: Recycle Bin via Shell API, component store via DISM.
3. **`ActiveProcesses` is a good idea** — Sweep keeps it as an advisory
   (`procs`) and reports which app to close instead of force-terminating it.
4. **`DetectOS` / `DetectFile` gating** inspired the "absent" reporting: a rule
   whose paths do not exist is shown as `–`, not as `0 B`.
5. **The caution concept.** Sweep formalises risk as
   `safe | moderate | caution`, with `caution` forbidden from being a default —
   which the test suite enforces.

## What Sweep refused to take

* Registry cleaning (no meaningful space, real breakage risk).
* Driver updating (silently swapping drivers is how machines break).
* Whole-profile browser matching (credentials, history, bookmarks).
* Telemetry, upsell surfaces, bundled browser, "PC health" scores.

---

## Method note

Static inspection only. The install directory, the plain-text ruleset, the
WebView2 chunk files and the configuration databases were read directly. The
Ghidra provider was bound to `CCleaner.exe` but its whole-program string and
procedure inventories exceeded the client's tool deadline on a 7.6 MB C++
image, so native pseudocode was not used for any conclusion here — the rule
file and the JavaScript are the authoritative behavioural artefacts, and they
were sufficient.
