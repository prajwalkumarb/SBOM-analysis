# run_demo.ps1 - Windows Runner for Inventory -> SBOM -> Grype

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Inventory Agent -> SBOM -> Grype (Windows)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Host "[1/3] Checking Python..." -ForegroundColor Yellow
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "  [FAIL] Python not found. Install from https://python.org" -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] Python found" -ForegroundColor Green

# Check Grype
Write-Host ""
Write-Host "[2/3] Checking Grype..." -ForegroundColor Yellow
$grype = Get-Command grype -ErrorAction SilentlyContinue

if (-not $grype) {
    Write-Host "  [WARN] Grype not found. Attempting install via winget..." -ForegroundColor Yellow

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        winget install Anchore.Grype
        Write-Host "  [OK] Grype installed. Restart PowerShell if grype is not found." -ForegroundColor Green
    } else {
        Write-Host "  [WARN] winget not available. Manual install steps:" -ForegroundColor Yellow
        Write-Host "      1. Go to: https://github.com/anchore/grype/releases" -ForegroundColor White
        Write-Host "      2. Download grype_windows_amd64.zip" -ForegroundColor White
        Write-Host "      3. Extract grype.exe and add to your PATH" -ForegroundColor White
        Write-Host ""
        Write-Host "  Continuing... SBOM will still be generated." -ForegroundColor Yellow
    }
} else {
    Write-Host "  [OK] Grype found" -ForegroundColor Green
    Write-Host "  Updating Grype vulnerability database..." -ForegroundColor Gray
    grype db update
}

# Run Python demo
Write-Host ""
Write-Host "[3/3] Running demo script..." -ForegroundColor Yellow
Set-Location $PSScriptRoot
python mock_inventory_agent.py

# Show output files
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Output Files:" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

$files = @("inventory_output.json", "sbom_output.json", "grype_report.json")
foreach ($f in $files) {
    if (Test-Path $f) {
        $size = (Get-Item $f).Length
        Write-Host "  [OK] $f ($size bytes)" -ForegroundColor Green
    } else {
        Write-Host "  [--] $f (not generated)" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "  To view SBOM:   cat sbom_output.json" -ForegroundColor White
Write-Host "  To re-scan:     grype sbom:sbom_output.json" -ForegroundColor White
Write-Host "  To block build: grype sbom:sbom_output.json --fail-on critical" -ForegroundColor White
Write-Host ""