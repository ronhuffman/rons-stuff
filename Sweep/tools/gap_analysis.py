"""Map CCleaner 7's category inventory against Sweep's rules to find real gaps."""

import collections
import re
import sys

INI = r"C:\Program Files\Piriform\CCleaner 7\ccleaner.ini"

sections = {}
cur = None
for ln in open(INI, encoding="utf-8", errors="replace"):
    s = ln.strip()
    if not s or s.startswith(";"):
        continue
    if s.startswith("[") and s.endswith("]"):
        cur = s[1:-1]
        sections[cur] = {}
    elif cur and "=" in s:
        k, v = s.split("=", 1)
        k = re.sub(r"\d+$", "", k.strip()).strip().lower()
        sections[cur].setdefault(k, []).append(v.strip())

print(f"total sections: {len(sections)}")

# classify
SYSTEM_TAGS = {"microsoft", "system", "ccsystem", "ccwindows", "network",
               "ccregistry", "registry", "ccwinstore"}
BROWSER_TAGS = {"browser", "edge", "firefox", "opera", "chrome", "internetcache",
                "cookies", "internethistory", "downloadhistory", "savedpasswords",
                "savedforminformation", "internetsession", "bookmarks",
                "lastdownloadlocation", "compactdatabases", "metrics"}

groups = collections.Counter()
system_sections = []
app_sections = []
browser_sections = []

for name, ent in sections.items():
    if name == "Rule Vars":
        continue
    tags = {t.strip().lower() for t in ",".join(ent.get("tags", [])).split(",")}
    if tags & BROWSER_TAGS:
        browser_sections.append((name, ent, tags))
        groups["browser"] += 1
    elif tags & SYSTEM_TAGS or ent.get("id", [""])[0].startswith(("windows.", "system.")):
        system_sections.append((name, ent, tags))
        groups["system"] += 1
    else:
        app_sections.append((name, ent, tags))
        groups["application"] += 1

print("classified:", dict(groups))
print()

# --- what system work does CCleaner do that involves non-file actions? ----
print("=" * 78)
print("SYSTEM SECTIONS WITH ACTION HANDLERS (capabilities Sweep must match)")
print("=" * 78)
for name, ent, tags in system_sections:
    acts = ent.get("action", [])
    if acts:
        print(f"  {name:44} default={ent.get('default',['-'])[0]:<6} "
              f"{'; '.join(acts)}")

print()
print("=" * 78)
print("ALL SYSTEM SECTIONS (name | default | #filekeys | #regkeys)")
print("=" * 78)
for name, ent, tags in sorted(system_sections, key=lambda t: t[0].lower()):
    print(f"  {name:46} d={ent.get('default',['-'])[0]:<6} "
          f"f={len(ent.get('filekey',[])):<3} r={len(ent.get('regkey',[])):<3} "
          f"{','.join(sorted(tags))[:44]}")

print()
print(f"APPLICATION sections: {len(app_sections)}")
for name, ent, tags in sorted(app_sections, key=lambda t: t[0].lower()):
    print(f"  {name:46} d={ent.get('default',['-'])[0]:<6} "
          f"f={len(ent.get('filekey',[])):<3} r={len(ent.get('regkey',[])):<3}")

print()
print(f"BROWSER sections: {len(browser_sections)}")
names = sorted({n for n, _e, _t in browser_sections})
for n in names:
    print("  ", n)
