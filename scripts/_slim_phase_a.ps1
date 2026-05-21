param()

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Skip($msg) { Write-Host "    [SKIP] $msg" -ForegroundColor DarkGray }

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$archiveRoot = Join-Path (Get-Location) 'archive'
$buildArchive = Join-Path $archiveRoot 'build-artifacts'
$runtimeArchive = Join-Path $archiveRoot 'runtime'
$benchArchive = Join-Path $archiveRoot 'benchmark_results'
$wsArchive = Join-Path $archiveRoot ("ctf_workspace_" + $stamp)

New-Item -ItemType Directory -Force -Path $buildArchive,$runtimeArchive,$benchArchive,$wsArchive | Out-Null

# --- 1. Python cache: delete ---
Write-Step "Removing __pycache__ directories..."
$pycDirs = Get-ChildItem -Path . -Directory -Recurse -Force -Filter __pycache__ -ErrorAction SilentlyContinue
$pycDirs | ForEach-Object {
    Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
Write-OK ("removed {0} __pycache__ dirs" -f $pycDirs.Count)

Write-Step "Removing standalone *.pyc files..."
$pycFiles = Get-ChildItem -Path . -File -Recurse -Force -Filter *.pyc -ErrorAction SilentlyContinue
$pycFiles | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
Write-OK ("removed {0} *.pyc files" -f $pycFiles.Count)

# --- 2. Test caches: delete ---
foreach ($d in @('.pytest_cache','.hypothesis')) {
    if (Test-Path $d) {
        Remove-Item -LiteralPath $d -Recurse -Force
        Write-OK "removed $d"
    } else {
        Write-Skip "$d not present"
    }
}

# --- 3. Build artifacts: archive ---
if (Test-Path 'build') {
    $dest = Join-Path $buildArchive ("build_" + $stamp)
    Move-Item -LiteralPath 'build' -Destination $dest
    Write-OK "archived build/ -> $dest"
} else { Write-Skip "build/ not present" }

if (Test-Path 'CET4StudyApp.exe') {
    $dest = Join-Path $buildArchive ("CET4StudyApp_" + $stamp + ".exe")
    Move-Item -LiteralPath 'CET4StudyApp.exe' -Destination $dest
    Write-OK "archived CET4StudyApp.exe -> $dest"
} else { Write-Skip "CET4StudyApp.exe not present" }

if (Test-Path 'CET4StudyApp.spec') {
    $dest = Join-Path $buildArchive ("CET4StudyApp_" + $stamp + ".spec")
    Move-Item -LiteralPath 'CET4StudyApp.spec' -Destination $dest
    Write-OK "archived CET4StudyApp.spec -> $dest"
} else { Write-Skip "CET4StudyApp.spec not present" }

# --- 4. reports / uploads: archive whole dirs ---
foreach ($d in @('reports','uploads')) {
    if (Test-Path $d) {
        $dest = Join-Path $runtimeArchive ($d + "_" + $stamp)
        Move-Item -LiteralPath $d -Destination $dest
        Write-OK "archived $d/ -> $dest"
        New-Item -ItemType Directory -Force -Path $d | Out-Null
        New-Item -ItemType File -Force -Path (Join-Path $d ".gitkeep") | Out-Null
    } else { Write-Skip "$d/ not present" }
}

# --- 5. benchmark_results: keep golden baseline, archive the rest ---
$goldenStems = @('benchmark_12_20260521_015335')
if (Test-Path 'benchmark_results') {
    $files = Get-ChildItem 'benchmark_results' -File -Force
    foreach ($f in $files) {
        $stem = [IO.Path]::GetFileNameWithoutExtension($f.Name)
        $keep = $false
        foreach ($g in $goldenStems) { if ($stem -eq $g) { $keep = $true; break } }
        if (-not $keep) {
            Move-Item -LiteralPath $f.FullName -Destination $benchArchive
        }
    }
    $remain = (Get-ChildItem 'benchmark_results' -File -Force).Count
    Write-OK ("benchmark_results trimmed -> {0} files remain (golden baseline)" -f $remain)

    # Also keep a 'latest' symlink-equivalent copy
    $golden = Join-Path 'benchmark_results' 'benchmark_12_20260521_015335.json'
    if (Test-Path $golden) {
        Copy-Item -LiteralPath $golden -Destination (Join-Path 'benchmark_results' 'benchmark_12_latest.json') -Force
        Write-OK "created benchmark_12_latest.json copy"
    }
}

# --- 6. ctf_workspace: archive top-level loose files, keep subdir scaffolding ---
if (Test-Path 'ctf_workspace') {
    $loose = Get-ChildItem 'ctf_workspace' -File -Force
    foreach ($f in $loose) {
        Move-Item -LiteralPath $f.FullName -Destination $wsArchive
    }
    Write-OK ("ctf_workspace top-level files archived -> {0} files" -f $loose.Count)
}

Write-Host ""
Write-Host "Phase A done." -ForegroundColor Green
