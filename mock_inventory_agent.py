"""
Inventory Agent -> SBOM -> Grype
- Windows installed apps  (registry, for inventory visibility)
- Python pip packages     (for real CVE matching via Grype)
"""

import json
import platform
import subprocess
import sys
import os
import winreg
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# STEP 1A: Windows Registry Apps
# ─────────────────────────────────────────────

REGISTRY_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]

def get_windows_apps():
    apps = []
    seen = set()
    for hive, path in REGISTRY_PATHS:
        try:
            key = winreg.OpenKey(hive, path)
        except FileNotFoundError:
            continue
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(key, subkey_name)
                def get_val(n):
                    try: return winreg.QueryValueEx(subkey, n)[0]
                    except: return None
                name      = get_val("DisplayName")
                version   = get_val("DisplayVersion") or "unknown"
                publisher = get_val("Publisher") or ""
                if not name or name in seen:
                    continue
                seen.add(name)
                apps.append({"name": name, "version": version, "publisher": publisher})
            except: continue
    return sorted(apps, key=lambda x: x["name"].lower())


# ─────────────────────────────────────────────
# STEP 1B: Python pip packages (real CVE data)
# ─────────────────────────────────────────────

def get_pip_packages():
    result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format=json"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return []
    return json.loads(result.stdout)  # [{"name": ..., "version": ...}]


# ─────────────────────────────────────────────
# STEP 1: COLLECT INVENTORY
# ─────────────────────────────────────────────

def collect_inventory():
    print("\n" + "="*62)
    print("  STEP 1: Inventory Agent - Collecting System Info")
    print("="*62)

    windows_apps = get_windows_apps()
    pip_packages  = get_pip_packages()

    inventory = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "system": {
            "hostname":     platform.node(),
            "os":           platform.system(),
            "os_version":   platform.version(),
            "architecture": platform.machine(),
            "python":       platform.python_version(),
        },
        "windows_apps": windows_apps,
        "pip_packages": pip_packages,
    }

    print(f"\n  Host         : {inventory['system']['hostname']}")
    print(f"  OS           : {inventory['system']['os']} {inventory['system']['os_version'][:40]}")
    print(f"  Arch         : {inventory['system']['architecture']}")

    print(f"\n  [A] Windows Installed Apps ({len(windows_apps)}) — Control Panel source:")
    for app in windows_apps[:10]:
        print(f"      {app['name']:<45} {app['version']}")
    if len(windows_apps) > 10:
        print(f"      ... and {len(windows_apps)-10} more (see inventory_output.json)")

    print(f"\n  [B] Python pip Packages ({len(pip_packages)}) — CVE-scannable:")
    for pkg in pip_packages:
        print(f"      {pkg['name']:<35} {pkg['version']}")

    with open("inventory_output.json", "w") as f:
        json.dump(inventory, f, indent=2)
    print(f"\n  [OK] Inventory saved -> inventory_output.json")

    return inventory


# ─────────────────────────────────────────────
# STEP 2: GENERATE CycloneDX SBOM
# Windows apps use pkg:generic (inventory only)
# pip packages use pkg:pypi   (CVE scannable)
# ─────────────────────────────────────────────

def generate_sbom(inventory):
    print("\n" + "="*62)
    print("  STEP 2: Generating CycloneDX SBOM")
    print("="*62)

    components = []

    # Windows apps — inventory visibility only
    for app in inventory["windows_apps"]:
        slug = app["name"].lower().replace(" ", "-")
        components.append({
            "type": "application",
            "name": app["name"],
            "version": app["version"],
            "publisher": app.get("publisher", ""),
            "purl": f"pkg:generic/{slug}@{app['version']}",
            "properties": [{"name": "source", "value": "windows-registry"}]
        })

    # pip packages — Grype will match these to CVE DB
    for pkg in inventory["pip_packages"]:
        components.append({
            "type": "library",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": f"pkg:pypi/{pkg['name'].lower()}@{pkg['version']}",
            "properties": [{"name": "source", "value": "pip"}]
        })

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:demo-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "version": 1,
        "metadata": {
            "timestamp": inventory["collected_at"],
            "component": {
                "type": "device",
                "name": inventory["system"]["hostname"],
                "version": inventory["system"]["os_version"]
            }
        },
        "components": components
    }

    with open("sbom_output.json", "w") as f:
        json.dump(sbom, f, indent=2)

    win_count = len(inventory["windows_apps"])
    pip_count = len(inventory["pip_packages"])
    print(f"\n  Components in SBOM:")
    print(f"    Windows apps (pkg:generic) : {win_count}  <- inventory only, not CVE-matched")
    print(f"    pip packages (pkg:pypi)    : {pip_count}  <- Grype will scan these")
    print(f"    Total                      : {win_count + pip_count}")
    print(f"\n  [OK] Saved -> sbom_output.json")
    return "sbom_output.json"


# ─────────────────────────────────────────────
# STEP 3: GRYPE SCAN
# ─────────────────────────────────────────────

def find_grype():
    import shutil
    if shutil.which("grype"):
        return "grype"
    candidates = [
        os.path.expanduser(r"~\AppData\Local\Microsoft\WinGet\Links\grype.exe"),
        r"C:\Program Files\grype\grype.exe",
        r"C:\grype\grype.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def run_grype(sbom_path):
    print("\n" + "="*62)
    print("  STEP 3: Grype - Vulnerability Scan")
    print("  (Only pkg:pypi components will match CVEs)")
    print("="*62)

    grype_cmd = find_grype()
    if not grype_cmd:
        print("\n  [WARN] Grype not found.")
        print("    Install: winget install Anchore.Grype")
        print(f"    Manual:  grype sbom:{sbom_path}")
        return

    print(f"\n  [OK] Grype: {grype_cmd}\n")
    subprocess.run([grype_cmd, f"sbom:{sbom_path}", "--output", "table"])

    json_result = subprocess.run(
        [grype_cmd, f"sbom:{sbom_path}", "--output", "json"],
        capture_output=True, text=True
    )
    with open("grype_report.json", "w") as f:
        f.write(json_result.stdout)

    if json_result.stdout:
        try:
            report   = json.loads(json_result.stdout)
            matches  = report.get("matches", [])
            critical = [m for m in matches if m.get("vulnerability", {}).get("severity", "").lower() == "critical"]
            high     = [m for m in matches if m.get("vulnerability", {}).get("severity", "").lower() == "high"]
            medium   = [m for m in matches if m.get("vulnerability", {}).get("severity", "").lower() == "medium"]

            print(f"\n  CVE Summary (pip packages only):")
            print(f"    Total    : {len(matches)}")
            print(f"    Critical : {len(critical)}")
            print(f"    High     : {len(high)}")
            print(f"    Medium   : {len(medium)}")
            print(f"  [OK] Full report -> grype_report.json")

            if critical:
                print("\n  [FAIL] CRITICAL CVEs found - BLOCK the build")
                sys.exit(1)
            elif len(matches) == 0:
                print("\n  [NOTE] 0 CVEs found.")
                print("         This is expected if your pip packages are up to date.")
                print("         Windows apps (pkg:generic) are not CVE-matched by Grype.")
            else:
                print("\n  [OK] No critical CVEs")
        except json.JSONDecodeError:
            pass


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    if platform.system() != "Windows":
        print("Windows only.")
        sys.exit(1)

    print("\n  ================================================")
    print("  Inventory Agent -> SBOM -> Grype")
    print("  ================================================")

    inventory = collect_inventory()
    sbom_path = generate_sbom(inventory)
    run_grype(sbom_path)

    print("\n" + "="*62)
    for f in ["inventory_output.json", "sbom_output.json", "grype_report.json"]:
        status = "OK" if os.path.exists(f) else "NOT FOUND"
        print(f"  [{status}] {f}")
    print("="*62 + "\n")