"""
Sweep - the built-in ruleset.

Every rule here was written from scratch against Windows/application
documentation and then validated against real directories on the host. The
guiding constraint is stricter than a typical cleaner's:

    A rule may only match bytes that the owning application can regenerate
    from its own state, or that Windows itself treats as disposable.

That is why there are no rules for:
  * registry keys ("registry cleaning" does not reclaim meaningful space and
    is a reliable way to break applications),
  * Firefox / Thunderbird profile bodies (logins.json, key4.db, places.sqlite
    hold credentials, bookmarks and history),
  * Chromium "User Data" as a whole (Login Data, Web Data, Bookmarks),
  * any directory that also stores documents or media.

Risk levels
-----------
safe      Regenerated automatically by the app or OS. No user-visible loss.
moderate  Diagnostic or download cache: nothing is lost, but it will be
          re-obtained (an update re-downloads, logs disappear).
caution   Removes a recovery/diagnostic artefact or forces a long rebuild.
          Off by default and never implicit.
"""

from __future__ import annotations

RISK_ORDER = {"safe": 0, "moderate": 1, "caution": 2}


def _f(path: str, pattern: str = "*", recurse: bool = True, remove_empty: bool = False) -> dict:
    return {"path": path, "pattern": pattern, "recurse": recurse, "remove_empty": remove_empty}


# --------------------------------------------------------------------------
# Chromium-family browsers share a profile layout. Building these from one
# template keeps the rules honest: we enumerate only cache directories, and
# the profile glob is scoped to real Chromium profile naming.
# --------------------------------------------------------------------------

_CHROMIUM_CACHE = (
    "Cache", "Code Cache", "GPUCache", "GrShaderCache", "ShaderCache",
    "DawnGraphiteCache", "DawnWebGPUCache", "Service Worker/CacheStorage",
    "Service Worker/ScriptCache", "Network/Cookies-journal",
)


def _chromium(userdata: str, procs: list[str]) -> list[dict]:
    files = []
    for sub in _CHROMIUM_CACHE:
        files.append(_f(f"{userdata}\\*\\{sub}"))
    return files


# Profiles that exist outside the per-profile loop.
_CHROMIUM_SHARED = ("ShaderCache", "GrShaderCache")


def chromium_rule(rid: str, name: str, userdata: str, procs: list[str], default: bool = True) -> dict:
    return {
        "id": rid,
        "name": name,
        "group": "Browsers",
        "risk": "safe",
        "default": default,
        "why": "Rendered pages, compiled JS and shaders are re-fetched on demand. "
               "Bookmarks, passwords, history and cookies are untouched.",
        "needs_admin": False,
        "procs": procs,
        "files": _chromium(userdata, procs),
    }


RULES: list[dict] = []


def add(rule: dict) -> None:
    RULES.append(rule)


# ==========================================================================
# Windows / system
# ==========================================================================

add({
    "id": "windows.temp",
    "name": "Temporary files",
    "group": "Windows",
    "risk": "safe",
    "default": True,
    "why": "Scratch files whose owning process has exited. In-use files are skipped.",
    "needs_admin": False,
    "files": [
        _f("%TEMP%"),
        _f("%WINDIR%\\Temp"),
        _f("%WINDIR%\\SystemTemp"),
    ],
})

add({
    "id": "windows.thumbnailcache",
    "name": "Thumbnail & icon cache",
    "group": "Windows",
    "risk": "safe",
    "default": True,
    "why": "Explorer rebuilds these the next time it draws a folder.",
    "needs_admin": False,
    "files": [
        _f("%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer", "thumbcache_*.db", recurse=False),
        _f("%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer", "iconcache_*.db", recurse=False),
    ],
})

add({
    "id": "windows.shadercache",
    "name": "GPU shader caches",
    "group": "Windows",
    "risk": "safe",
    "default": True,
    "why": "Compiled shader blobs; games and the desktop rebuild them on first use.",
    "needs_admin": False,
    "files": [
        _f("%LOCALAPPDATA%\\D3DSCache"),
        _f("%LOCALAPPDATA%\\Microsoft\\DirectX\\ShaderCache"),
        _f("%LOCALAPPDATA%\\NVIDIA\\DXCache"),
        _f("%LOCALAPPDATA%\\NVIDIA\\GLCache"),
        _f("%LOCALAPPDATA%\\NVIDIA Corporation\\NV_Cache"),
        _f("%LOCALAPPDATA%\\AMD\\DxCache"),
        _f("%LOCALAPPDATA%\\AMD\\DxcCache"),
        _f("%LOCALAPPDATA%\\AMD\\GLCache"),
        _f("%LOCALAPPDATA%\\Intel\\ShaderCache"),
    ],
})

add({
    "id": "windows.wer",
    "name": "Error reporting queue",
    "group": "Windows",
    "risk": "moderate",
    "default": True,
    "why": "Crash reports waiting to be uploaded. Nothing that has already been "
           "submitted is affected, but the report itself is not preserved.",
    "needs_admin": False,
    "files": [
        _f("%LOCALAPPDATA%\\Microsoft\\Windows\\WER\\ReportArchive"),
        _f("%LOCALAPPDATA%\\Microsoft\\Windows\\WER\\ReportQueue"),
        _f("%LOCALAPPDATA%\\Microsoft\\Windows\\WER\\Temp"),
        _f("%ALLUSERSPROFILE%\\Microsoft\\Windows\\WER\\ReportArchive"),
        _f("%ALLUSERSPROFILE%\\Microsoft\\Windows\\WER\\ReportQueue"),
        _f("%ALLUSERSPROFILE%\\Microsoft\\Windows\\WER\\Temp"),
    ],
})

add({
    "id": "windows.crashdumps",
    "name": "Application crash dumps",
    "group": "Windows",
    "risk": "moderate",
    "default": True,
    "why": "Post-mortem dumps from crashed apps. Only useful to a developer if "
           "you are actively debugging that app.",
    "needs_admin": False,
    "files": [
        _f("%LOCALAPPDATA%\\CrashDumps"),
        _f("%LOCALAPPDATA%\\Microsoft\\Windows\\WER\\Temp"),
    ],
})

add({
    "id": "windows.memorydumps",
    "name": "Kernel memory dumps",
    "group": "Windows",
    "risk": "moderate",
    "default": False,
    "why": "A full RAM image from the last blue screen. Can be as large as your "
           "installed memory. Disable the crash-dump setting if it reappears.",
    "needs_admin": True,
    "files": [
        _f("%WINDIR%", "MEMORY.DMP", recurse=False),
        _f("%WINDIR%\\Minidump", "*.dmp"),
        _f("%WINDIR%\\LiveKernelReports", "*.dmp"),
    ],
})

add({
    "id": "windows.updatecache",
    "name": "Windows Update download cache",
    "group": "Windows",
    "risk": "moderate",
    "default": True,
    "why": "Already-installed update payloads kept for re-apply. Windows "
           "re-downloads anything it still needs.",
    "needs_admin": True,
    "files": [
        _f("%WINDIR%\\SoftwareDistribution\\Download"),
    ],
})

add({
    "id": "windows.deliveryoptimization",
    "name": "Delivery Optimization cache",
    "group": "Windows",
    "risk": "safe",
    "default": True,
    "why": "Update fragments shared peer-to-peer on your LAN. Purely a cache.",
    "needs_admin": True,
    "files": [
        _f("%WINDIR%\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache"),
        _f("%WINDIR%\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Logs", "*.etl"),
        _f("%WINDIR%\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\State", "*.log"),
    ],
})

add({
    "id": "windows.logs",
    "name": "Windows component logs",
    "group": "Windows",
    "risk": "moderate",
    "default": True,
    "why": "CBS/DISM/update logs. Occasionally useful for diagnosing a failed "
           "update, otherwise pure text accumulation.",
    "needs_admin": True,
    "files": [
        _f("%WINDIR%\\Logs\\CBS", "*.log"),
        _f("%WINDIR%\\Logs\\CBS", "*.cab"),
        _f("%WINDIR%\\Logs\\DISM", "*.log"),
        _f("%WINDIR%\\Logs\\DISM", "*.etl"),
        _f("%WINDIR%\\Logs\\WindowsUpdate", "*.etl"),
        _f("%WINDIR%\\Logs\\MoSetup", "*.log"),
        _f("%WINDIR%\\Logs\\SIH", "*.log"),
        _f("%WINDIR%\\Logs\\waasmedic", "*.etl"),
        # Top-level setup logs plus the monitor log directory. Deliberately not
        # recursive over Panther as a whole: Panther\Rollback holds the EFI
        # payload used to roll a failed upgrade back.
        _f("%WINDIR%\\Panther", "*.log;*.etl", recurse=False),
        _f("%WINDIR%\\Panther\\monitor", "*.log"),
        _f("%WINDIR%\\System32\\LogFiles\\WMI", "*.etl"),
    ],
})

add({
    "id": "windows.setupcache",
    "name": "Upgrade & setup caches",
    "group": "Windows",
    "risk": "moderate",
    "default": True,
    "why": "Rollback payload left behind by a feature update that already "
           "completed successfully.",
    "needs_admin": True,
    "files": [
        _f("%WINDIR%\\Panther\\UnattendGC"),
        _f("C:\\$WINDOWS.~BT\\Sources\\Panther", "*.log"),
        _f("C:\\$WINDOWS.~WS\\Sources\\Panther", "*.log"),
        _f("%WINDIR%\\SoftwareDistribution\\DataStore\\Logs", "*.edb"),
        _f("%WINDIR%\\SoftwareDistribution\\DataStore\\Logs", "*.jrs"),
    ],
})

add({
    "id": "windows.chkdsk",
    "name": "Chkdsk recovery fragments",
    "group": "Windows",
    "risk": "safe",
    "default": True,
    "why": "Orphaned file fragments from an interrupted disk check.",
    "needs_admin": True,
    "files": [
        _f("C:\\", "found.*.chk", recurse=False),
        _f("%WINDIR%", "found.*.chk", recurse=False),
    ],
})

add({
    "id": "windows.patchcache",
    "name": "Installer patch cache",
    "group": "Windows",
    "risk": "moderate",
    "default": False,
    "why": "Superseded MSI patch payloads. Modern installers rarely need them, "
           "but an old repair/uninstall may ask for the original media.",
    "needs_admin": True,
    "files": [
        _f("%WINDIR%\\Installer\\$PatchCache$"),
    ],
})

add({
    "id": "windows.defenderhistory",
    "name": "Defender scan history",
    "group": "Windows",
    "risk": "safe",
    "default": True,
    "why": "Resolved detection records from Defender's own scan log.",
    "needs_admin": True,
    "files": [
        _f("%PROGRAMDATA%\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory"),
        _f("%PROGRAMDATA%\\Microsoft\\Windows Defender\\Scans\\History\\ResourceData"),
    ],
})

add({
    "id": "windows.prefetch",
    "name": "Prefetch data",
    "group": "Windows",
    "risk": "caution",
    "default": False,
    "why": "Launch traces Windows uses to speed up app startup. Deleting them "
           "makes the next few launches slower. Do not clean this routinely.",
    "needs_admin": True,
    "files": [
        _f("%WINDIR%\\Prefetch", "*.pf"),
    ],
})

add({
    "id": "windows.fontcache",
    "name": "Font cache",
    "group": "Windows",
    "risk": "caution",
    "default": False,
    "why": "Rebuilt on next boot. Can help when glyphs render incorrectly; "
           "otherwise there is nothing to gain.",
    "needs_admin": True,
    "files": [
        _f("%WINDIR%\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache", "*.dat"),
    ],
})

add({
    "id": "windows.retaildemo",
    "name": "Retail demo content",
    "group": "Windows",
    "risk": "safe",
    "default": True,
    "why": "Store demo videos preloaded for retail display units.",
    "needs_admin": True,
    "files": [
        _f("%WINDIR%\\System32\\Configuration\\RetailDemo"),
        _f("%PROGRAMDATA%\\Microsoft\\Windows\\RetailDemo"),
    ],
})

add({
    "id": "windows.windowsold",
    "name": "Previous Windows installation",
    "group": "Windows",
    "risk": "caution",
    "default": False,
    "why": "The full previous OS kept for rollback. Often tens of GB. After this "
           "you cannot un-upgrade - make sure the current build is stable first.",
    "needs_admin": True,
    "files": [
        _f("C:\\Windows.old"),
        _f("C:\\$WINDOWS.~BT"),
        _f("C:\\$WINDOWS.~WS"),
        _f("C:\\$Windows.~WS"),
        _f("C:\\ESD"),
    ],
})

add({
    "id": "windows.recyclebin",
    "name": "Recycle Bin",
    "group": "Windows",
    "risk": "caution",
    "default": False,
    "why": "Everything you deleted but did not commit. This is the one rule that "
           "can destroy recoverable user files, so it is never on by default.",
    "needs_admin": False,
    "files": [],
    "action": "empty_recycle_bin",
})

add({
    "id": "windows.dnscache",
    "name": "DNS resolver cache",
    "group": "Windows",
    "risk": "safe",
    "default": False,
    "why": "Reclaims no disk space; flushes stale name-resolution entries. "
           "Useful after changing hosts/DNS, pointless as routine cleaning.",
    "needs_admin": False,
    "files": [],
    "action": "flush_dns",
})

add({
    "id": "windows.winsxs",
    "name": "Component store cleanup (WinSxS)",
    "group": "Windows",
    "risk": "caution",
    "default": False,
    "why": "Removes superseded component versions via DISM. This is the largest "
           "legitimate system win (often several GB) but it takes many minutes "
           "and permanently removes the ability to uninstall installed updates.",
    "needs_admin": True,
    "files": [],
    "action": "dism_component_cleanup",
    "long_running": True,
})

# ==========================================================================
# Browsers
# ==========================================================================

add(chromium_rule(
    "browser.chrome", "Google Chrome cache",
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data",
    ["chrome.exe"],
))

add(chromium_rule(
    "browser.edge", "Microsoft Edge cache",
    "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data",
    ["msedge.exe"],
))

add(chromium_rule(
    "browser.brave", "Brave cache",
    "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data",
    ["brave.exe"],
))

add(chromium_rule(
    "browser.vivaldi", "Vivaldi cache",
    "%LOCALAPPDATA%\\Vivaldi\\User Data",
    ["vivaldi.exe"],
))

add(chromium_rule(
    "browser.chromium", "Chromium cache",
    "%LOCALAPPDATA%\\Chromium\\User Data",
    ["chromium.exe"],
))

add({
    "id": "browser.firefox",
    "name": "Firefox cache",
    "group": "Browsers",
    "risk": "safe",
    "default": True,
    "why": "Only cache2/startupCache/shader-cache are touched. The profile "
           "itself - logins.json, key4.db, places.sqlite - is never matched.",
    "needs_admin": False,
    "procs": ["firefox.exe"],
    "files": [
        _f("%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*\\cache2"),
        _f("%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*\\startupCache"),
        _f("%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*\\shader-cache"),
        _f("%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*\\thumbnails"),
        _f("%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*\\crashes"),
        _f("%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*\\OfflineCache"),
        _f("%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*\\jumpListCache"),
        _f("%APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\startupCache"),
        _f("%LOCALAPPDATA%\\Mozilla\\Thunderbird\\Profiles\\*\\startupCache"),
    ],
})

add({
    "id": "browser.opera",
    "name": "Opera cache",
    "group": "Browsers",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "procs": ["opera.exe"],
    "why": "Cache directories only.",
    "files": [
        _f("%APPDATA%\\Opera Software\\Opera Stable\\Cache"),
        _f("%APPDATA%\\Opera Software\\Opera Stable\\Code Cache"),
        _f("%APPDATA%\\Opera Software\\Opera Stable\\GPUCache"),
        _f("%APPDATA%\\Opera Software\\Opera GX Stable\\Cache"),
        _f("%APPDATA%\\Opera Software\\Opera GX Stable\\Code Cache"),
        _f("%APPDATA%\\Opera Software\\Opera GX Stable\\GPUCache"),
    ],
})

add({
    "id": "privacy.history",
    "name": "Browsing history & download list",
    "group": "Privacy",
    "risk": "caution",
    "default": False,
    "why": "This is not junk - it is your record. Deleting it is a privacy choice, "
           "not a space cleanup. Off by default, and never batched with cleaning.",
    "needs_admin": False,
    "procs": ["chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "firefox.exe", "opera.exe"],
    "files": [
        _f("%LOCALAPPDATA%\\Google\\Chrome\\User Data\\*", "History", recurse=False),
        _f("%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\*", "History", recurse=False),
        _f("%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\*", "History", recurse=False),
        _f("%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*", "places.sqlite", recurse=False),
    ],
})

add({
    "id": "privacy.cookies",
    "name": "Cookies & site data",
    "group": "Privacy",
    "risk": "caution",
    "default": False,
    "why": "Signs you out of every site. Privacy choice, not a disk cleanup. "
           "Add domains to the keep-list and those logins survive.",
    "needs_admin": False,
    "handler": "cookie_dbs",
    "procs": ["chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "firefox.exe", "opera.exe"],
    "files": [
        _f("%LOCALAPPDATA%\\Google\\Chrome\\User Data\\*\\Network", "Cookies", recurse=False),
        _f("%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\*\\Network", "Cookies", recurse=False),
        _f("%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\*\\Network", "Cookies", recurse=False),
        _f("%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*", "cookies.sqlite", recurse=False),
    ],
})

# ==========================================================================
# Developer caches - where modern machines actually accumulate junk
# ==========================================================================

add({
    "id": "dev.pip",
    "name": "pip download cache",
    "group": "Developer",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "why": "Wheels already installed. pip re-downloads on demand.",
    "files": [_f("%LOCALAPPDATA%\\pip\\Cache")],
})

add({
    "id": "dev.npm",
    "name": "npm cache",
    "group": "Developer",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "why": "Content-addressed package blobs. `npm ci` re-fetches as needed.",
    "files": [
        _f("%LOCALAPPDATA%\\npm-cache"),
        _f("%APPDATA%\\npm-cache"),
    ],
})

add({
    "id": "dev.yarn",
    "name": "Yarn cache",
    "group": "Developer",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "why": "Downloaded package archives.",
    "files": [
        _f("%LOCALAPPDATA%\\Yarn\\Cache"),
        _f("%LOCALAPPDATA%\\Yarn\\berry\\cache"),
    ],
})

add({
    "id": "dev.pnpm",
    "name": "pnpm store",
    "group": "Developer",
    "risk": "moderate",
    "default": False,
    "needs_admin": False,
    "why": "Global content store shared by every pnpm project. Deleting it "
           "requires a full re-install of all projects that use it.",
    "files": [_f("%LOCALAPPDATA%\\pnpm\\store")],
})

add({
    "id": "dev.nuget",
    "name": "NuGet package cache",
    "group": "Developer",
    "risk": "moderate",
    "default": False,
    "needs_admin": False,
    "why": "Extracted packages under ~\\.nuget\\packages. Projects still build, "
           "but every restore re-downloads.",
    "files": [_f("%USERPROFILE%\\.nuget\\packages")],
})

add({
    "id": "dev.cargo",
    "name": "Cargo registry cache",
    "group": "Developer",
    "risk": "moderate",
    "default": False,
    "needs_admin": False,
    "why": "Downloaded .crate archives. Extracted sources under registry\\src "
           "are intentionally left in place.",
    "files": [
        _f("%USERPROFILE%\\.cargo\\registry\\cache"),
        _f("%USERPROFILE%\\.cargo\\registry\\index"),
    ],
})

add({
    "id": "dev.go",
    "name": "Go build & module cache",
    "group": "Developer",
    "risk": "moderate",
    "default": False,
    "needs_admin": False,
    "why": "Compile cache and downloaded modules. The next build is simply slower.",
    "files": [
        _f("%LOCALAPPDATA%\\go-build"),
        _f("%USERPROFILE%\\go\\pkg\\mod\\cache"),
    ],
})

add({
    "id": "dev.gradle",
    "name": "Gradle cache",
    "group": "Developer",
    "risk": "moderate",
    "default": False,
    "needs_admin": False,
    "why": "Resolved dependencies and build caches. Next sync re-downloads.",
    "files": [
        _f("%USERPROFILE%\\.gradle\\caches"),
    ],
})

add({
    "id": "dev.vscode",
    "name": "VS Code / Cursor caches",
    "group": "Developer",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "why": "Renderer caches and old log files. Extensions and settings untouched.",
    "files": [
        _f("%APPDATA%\\Code\\Cache"),
        _f("%APPDATA%\\Code\\Code Cache"),
        _f("%APPDATA%\\Code\\GPUCache"),
        _f("%APPDATA%\\Code\\CachedData"),
        _f("%APPDATA%\\Code\\logs"),
        _f("%APPDATA%\\Cursor\\Cache"),
        _f("%APPDATA%\\Cursor\\Code Cache"),
        _f("%APPDATA%\\Cursor\\GPUCache"),
        _f("%APPDATA%\\Cursor\\CachedData"),
        _f("%APPDATA%\\Cursor\\logs"),
        _f("%APPDATA%\\Windsurf\\Cache"),
        _f("%APPDATA%\\Windsurf\\Code Cache"),
        _f("%APPDATA%\\Windsurf\\GPUCache"),
        _f("%APPDATA%\\Windsurf\\logs"),
    ],
})

add({
    "id": "dev.jetbrains",
    "name": "JetBrains IDE caches & logs",
    "group": "Developer",
    "risk": "moderate",
    "default": False,
    "needs_admin": False,
    "why": "Index caches are rebuilt on next project open. Settings, plugins and "
           "projects are not touched.",
    "files": [
        _f("%LOCALAPPDATA%\\JetBrains\\*\\caches"),
        _f("%LOCALAPPDATA%\\JetBrains\\*\\log"),
        _f("%LOCALAPPDATA%\\JetBrains\\*\\tmp"),
    ],
})

add({
    "id": "dev.vs",
    "name": "Visual Studio caches",
    "group": "Developer",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "why": "Component and MEF caches, plus the telemetry/activity log.",
    "files": [
        _f("%LOCALAPPDATA%\\Microsoft\\VisualStudio\\*\\ComponentModelCache"),
        _f("%LOCALAPPDATA%\\Microsoft\\VisualStudio\\*\\Temp"),
        _f("%APPDATA%\\Microsoft\\VisualStudio\\*\\FileCache"),
    ],
})

# ==========================================================================
# Applications
# ==========================================================================

add({
    "id": "app.teams",
    "name": "Microsoft Teams cache",
    "group": "Apps",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "procs": ["teams.exe", "ms-teams.exe"],
    "why": "Renderer and GPU caches. Sign-in state and message history are server-side.",
    "files": [
        _f("%APPDATA%\\Microsoft\\Teams\\Cache"),
        _f("%APPDATA%\\Microsoft\\Teams\\Code Cache"),
        _f("%APPDATA%\\Microsoft\\Teams\\GPUCache"),
        _f("%APPDATA%\\Microsoft\\Teams\\logs"),
        _f("%APPDATA%\\Microsoft\\Teams\\tmp"),
        _f("%LOCALAPPDATA%\\Microsoft\\Teams\\Cache"),
        _f("%LOCALAPPDATA%\\Microsoft\\Teams\\Code Cache"),
        _f("%LOCALAPPDATA%\\Microsoft\\Teams\\GPUCache"),
        _f("%LOCALAPPDATA%\\Microsoft\\Teams\\logs"),
        _f("%LOCALAPPDATA%\\Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams\\Cache"),
        _f("%LOCALAPPDATA%\\Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams\\logs"),
    ],
})

add({
    "id": "app.slack",
    "name": "Slack cache",
    "group": "Apps",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "procs": ["slack.exe"],
    "why": "Renderer caches and logs.",
    "files": [
        _f("%APPDATA%\\Slack\\Cache"),
        _f("%APPDATA%\\Slack\\Code Cache"),
        _f("%APPDATA%\\Slack\\GPUCache"),
        _f("%APPDATA%\\Slack\\logs"),
    ],
})

add({
    "id": "app.discord",
    "name": "Discord cache",
    "group": "Apps",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "procs": ["discord.exe", "discordcanary.exe", "discordptb.exe"],
    "why": "Renderer caches and logs.",
    "files": [
        _f("%APPDATA%\\discord\\Cache"),
        _f("%APPDATA%\\discord\\Code Cache"),
        _f("%APPDATA%\\discord\\GPUCache"),
        _f("%APPDATA%\\discord\\logs"),
        _f("%APPDATA%\\discordptb\\Cache"),
        _f("%APPDATA%\\discordptb\\Code Cache"),
        _f("%APPDATA%\\discordcanary\\Cache"),
    ],
})

add({
    "id": "app.spotify",
    "name": "Spotify cache",
    "group": "Apps",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "procs": ["spotify.exe"],
    "why": "Streamed track buffer. Re-streams on demand; downloads are separate.",
    "files": [
        _f("%LOCALAPPDATA%\\Spotify\\Data"),
        _f("%LOCALAPPDATA%\\Spotify\\Storage"),
        _f("%LOCALAPPDATA%\\Packages\\SpotifyAB.SpotifyMusic_zpdnekdrzrea0\\LocalCache\\Spotify\\Data"),
    ],
})

add({
    "id": "app.steam",
    "name": "Steam shader & browser cache",
    "group": "Apps",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "procs": ["steam.exe", "steamwebhelper.exe"],
    "why": "Precompiled shaders and the in-client browser cache. Games are untouched.",
    "files": [
        _f("%LOCALAPPDATA%\\Steam\\htmlcache"),
        _f("%PROGRAMFILES(X86)%\\Steam\\steamapps\\shadercache"),
    ],
})

add({
    "id": "app.onedrive",
    "name": "OneDrive logs",
    "group": "Apps",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "procs": ["onedrive.exe"],
    "why": "Sync logs. Your files in the cloud and on disk are unaffected.",
    "files": [
        _f("%LOCALAPPDATA%\\Microsoft\\OneDrive\\logs"),
        _f("%LOCALAPPDATA%\\Microsoft\\OneDrive\\setup\\logs"),
    ],
})

add({
    "id": "app.office",
    "name": "Office document cache",
    "group": "Apps",
    "risk": "safe",
    "default": False,
    "needs_admin": False,
    "procs": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
    "why": "Local document cache used for offline editing. Safe, but unsynced "
           "edits could be lost if Office is closed abruptly.",
    "files": [
        _f("%LOCALAPPDATA%\\Microsoft\\Office\\*\\OfficeFileCache"),
        _f("%LOCALAPPDATA%\\Microsoft\\Office\\*\\PowerPoint\\*"),
    ],
})

add({
    "id": "app.zoom",
    "name": "Zoom cache & logs",
    "group": "Apps",
    "risk": "safe",
    "default": True,
    "needs_admin": False,
    "procs": ["zoom.exe"],
    "why": "Meeting caches and logs.",
    "files": [
        _f("%APPDATA%\\Zoom\\logs"),
        _f("%APPDATA%\\Zoom\\data"),
    ],
})


# --------------------------------------------------------------------------
# query helpers
# --------------------------------------------------------------------------

def by_group() -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for r in RULES:
        groups.setdefault(r["group"], []).append(r)
    return groups


def get(rule_id: str) -> dict | None:
    for r in RULES:
        if r["id"] == rule_id:
            return r
    return None


def defaults() -> list[dict]:
    """Rules that are on unless the user says otherwise.

    Imported rules are excluded: they come from a third-party file, so they run
    only when explicitly selected via --all, --imported or --rules.
    """
    return [r for r in RULES if r.get("default") and not r.get("imported")]


def ids() -> list[str]:
    return [r["id"] for r in RULES]


# --------------------------------------------------------------------------
# external (imported) rules
# --------------------------------------------------------------------------

#: Rule files loaded from disk, in load order.
EXTERNAL: list[str] = []


def load_external(path: str) -> int:
    """Append rules from a Sweep-format rule file (see `sweep import`)."""
    from . import ccimport

    loaded, _blob = ccimport.load(path)
    known = {r["id"] for r in RULES}
    added = 0
    for r in loaded:
        rid = r["id"]
        if rid in known:
            n = 2
            while f"{rid}~{n}" in known:
                n += 1
            r["id"] = f"{rid}~{n}"
            rid = r["id"]
        known.add(rid)
        RULES.append(r)
        added += 1
    EXTERNAL.append(path)
    return added


def unload_external() -> None:
    RULES[:] = [r for r in RULES if not r.get("imported")]
    EXTERNAL.clear()


def is_external(rule_id: str) -> bool:
    r = get(rule_id)
    return bool(r and r.get("imported"))
