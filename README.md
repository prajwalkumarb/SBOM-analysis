# SBOM Security Scanner
**Inventory Agent → SBOM → Grype → Dashboard**

A lightweight Windows tool that collects installed software from your system, generates a Software Bill of Materials (SBOM), scans it for vulnerabilities using Grype, and displays results in a browser dashboard.

---

## Project Files

| File | Purpose |
|---|---|
| `mock_inventory_agent.py` | Main script — collects apps, generates SBOM, runs Grype |
| `run_demo.ps1` | PowerShell runner — installs Grype if missing, then runs the script |
| `sbom_report.html` | Customer-facing dashboard — open in browser to view results |
| `inventory_output.json` | Generated — raw inventory data from your system |
| `sbom_output.json` | Generated — CycloneDX 1.4 SBOM document |
| `grype_report.json` | Generated — CVE scan results from Grype |

---

## Prerequisites

- **Python 3.8+** — https://python.org
- **Grype** — install via PowerShell (Admin):
  ```powershell
  winget install Anchore.Grype
  ```
  Then restart PowerShell so `grype` is available on PATH.

---

## How to Run

### Step 1 — Set execution policy (one-time, Admin PowerShell)
```powershell
Set-ExecutionPolicy RemoteSigned
```

### Step 2 — Navigate to project folder
```powershell
cd E:\SBOM
```

### Step 3 — Run the script
```powershell
.\run_demo.ps1
```

Or run the Python script directly:
```powershell
python mock_inventory_agent.py
```

---

## What Happens When You Run It

```
Step 1 — Inventory Agent
         Reads Windows Registry (same source as Control Panel)
         Reads pip packages from current Python environment
         Saves → inventory_output.json

Step 2 — SBOM Generation
         Converts inventory into CycloneDX 1.4 JSON format
         Windows apps  → pkg:generic (inventory visibility)
         pip packages  → pkg:pypi    (CVE-scannable)
         Saves → sbom_output.json

Step 3 — Grype CVE Scan
         Scans sbom_output.json against Grype vulnerability database
         pkg:pypi components are matched against known CVEs
         Saves → grype_report.json
         Exits with code 1 if any CRITICAL CVEs are found (build gate)
```

---

## Viewing the Dashboard

Once the 3 JSON files are generated, open the dashboard:

### Step 1 — Open the HTML file
Double-click `sbom_report.html`
It will open in your default browser (Edge, Chrome, etc.)

### Step 2 — Upload your scan files
You will see an upload screen with 3 buttons:

```
[ inventory_output.json ]  [ sbom_output.json ]  [ grype_report.json ]
```

Click each button and select the matching file from `E:\SBOM\`:

| Button | File to select |
|---|---|
| inventory_output.json | `E:\SBOM\inventory_output.json` |
| sbom_output.json | `E:\SBOM\sbom_output.json` |
| grype_report.json | `E:\SBOM\grype_report.json` |

### Step 3 — View the dashboard
After all 3 files are loaded, the dashboard renders automatically showing:

- **Device Info** — hostname, OS, scan timestamp
- **Vulnerability Summary** — counts by severity (Critical / High / Medium / Low)
- **CVE Findings** — each vulnerability with advisory ID, description, fix version
- **Components Table** — all apps searchable and filterable by source (pip / Windows)

> Tip: Click **"Load Demo Data"** to preview the dashboard without uploading files.

---

## Understanding the CVE Results

```
NAME    INSTALLED   FIXED IN   SEVERITY   MEANING
pip     24.2        25.3       Medium     pip itself has a known vulnerability
                                          Fix: run  python -m pip install --upgrade pip
```

- **Fixed** status means a patched version is available — upgrade to resolve
- **Not-fixed** means no patch exists yet — monitor for updates
- **pkg:generic** components (Windows apps) show 0 CVEs — Grype does not have a
  Windows installer ecosystem; use Microsoft Defender or Tenable for those

---

## Build Gate Usage

To block a build pipeline if critical CVEs are found:

```powershell
grype sbom:sbom_output.json --fail-on critical
```

Exit code `0` = safe to proceed
Exit code `1` = critical CVEs found, block the build

---

## Output File Reference

### inventory_output.json
```json
{
  "collected_at": "2026-06-22T05:46:05+00:00",
  "system": { "hostname": "...", "os": "Windows", ... },
  "windows_apps": [ { "name": "Google Chrome", "version": "126.0" } ],
  "pip_packages": [ { "name": "pip", "version": "24.2" } ]
}
```

### sbom_output.json
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    { "name": "pip", "version": "24.2", "purl": "pkg:pypi/pip@24.2" }
  ]
}
```

### grype_report.json
```json
{
  "matches": [
    {
      "vulnerability": { "id": "GHSA-xxxx", "severity": "Medium", "fix": { "versions": ["25.3"] } },
      "artifact": { "name": "pip", "version": "24.2" }
    }
  ]
}
```

---

## Architecture Overview

```
Windows Registry ──┐
                   ├──► inventory_output.json
pip list      ─────┘           │
                               ▼
                       sbom_output.json  (CycloneDX 1.4)
                               │
                               ▼
                            Grype
                               │
                               ▼
                       grype_report.json
                               │
                               ▼
                       sbom_report.html  (Browser Dashboard)
```

---

## Troubleshooting

**Grype not found after winget install**
Close PowerShell completely and reopen — PATH updates require a new session.

**0 vulnerabilities found for Windows apps**
Expected. Grype matches `pkg:pypi`, `pkg:npm`, `pkg:deb` etc. — not `pkg:generic`.
Windows apps require CPE-based scanners (Microsoft Defender Vulnerability Management).

**Script won't run — execution policy error**
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Grype database is stale**
```powershell
grype db update
```
