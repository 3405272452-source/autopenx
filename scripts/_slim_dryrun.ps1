param()

$ErrorActionPreference = 'SilentlyContinue'

function Get-Size($path) {
    if (-not (Test-Path $path)) { return $null }
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer) {
        return (Get-ChildItem -LiteralPath $path -Recurse -Force | Measure-Object -Property Length -Sum).Sum
    }
    return $item.Length
}

$paths = @(
    '.venv',
    'build',
    'CET4StudyApp.exe',
    'reports',
    'uploads',
    '.pytest_cache',
    '.hypothesis',
    'benchmark_results',
    'ctf_workspace'
)

Write-Host "=== Slim Dry-Run Inventory ===" -ForegroundColor Cyan
$total = 0.0
foreach ($p in $paths) {
    $s = Get-Size $p
    if ($null -eq $s) {
        '{0,-22} (not present)' -f $p
    } else {
        $mb = [math]::Round($s / 1MB, 2)
        $total += $mb
        '{0,-22} {1,10:N2} MB' -f $p, $mb
    }
}

# __pycache__ + .pyc
$pycDirs = Get-ChildItem -Path . -Directory -Recurse -Force -Filter __pycache__
$pycSize = 0
foreach ($d in $pycDirs) {
    $pycSize += (Get-ChildItem -LiteralPath $d.FullName -Recurse -Force | Measure-Object -Property Length -Sum).Sum
}
$pycFileSize = (Get-ChildItem -Path . -File -Recurse -Force -Filter *.pyc | Measure-Object -Property Length -Sum).Sum
'{0,-22} {1,10:N2} MB ({2} dirs)' -f '__pycache__', ($pycSize / 1MB), $pycDirs.Count
'{0,-22} {1,10:N2} MB' -f '*.pyc (standalone)', ($pycFileSize / 1MB)
$total += [math]::Round(($pycSize + $pycFileSize) / 1MB, 2)

Write-Host ""
Write-Host ("TOTAL CANDIDATES: ~{0:N2} MB" -f $total) -ForegroundColor Yellow

Write-Host ""
Write-Host "=== benchmark_results contents ===" -ForegroundColor Cyan
if (Test-Path benchmark_results) {
    Get-ChildItem benchmark_results -Force | Sort-Object Length -Descending | Format-Table Name, Length, LastWriteTime -AutoSize
}

Write-Host ""
Write-Host "=== reports contents (top-level) ===" -ForegroundColor Cyan
if (Test-Path reports) {
    Get-ChildItem reports -Force | Format-Table Name, Length, LastWriteTime -AutoSize
}

Write-Host ""
Write-Host "=== uploads contents (top-level) ===" -ForegroundColor Cyan
if (Test-Path uploads) {
    Get-ChildItem uploads -Force | Format-Table Name, Length, LastWriteTime -AutoSize
}

Write-Host ""
Write-Host "=== ctf_workspace contents (top-level) ===" -ForegroundColor Cyan
if (Test-Path ctf_workspace) {
    Get-ChildItem ctf_workspace -Force | Format-Table Name, Length, LastWriteTime -AutoSize
}
