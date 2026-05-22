#Requires -Version 5.1
<#
.SYNOPSIS
    AutoPenX one-click verification script.
    Runs all quality gates and reports pass/fail summary.

.DESCRIPTION
    Executes 6 gates in order:
      1. ruff_lint       - Lint check with ruff
      2. import_check    - Verify core imports work
      3. regression      - Run regression test suite
      4. strict_12       - Run strict 12-target web benchmark
      5. real_ctf_30     - Run full 30-target real CTF benchmark
      6. coverage        - Verify coverage report was generated

    All gates run regardless of prior failures. A summary table is printed
    at the end with a final verdict.

.NOTES
    Run from the project root with an activated Python venv.
    Usage: .\scripts\verify_all.ps1
#>

# --- Configuration -----------------------------------------------------------

# Set working directory to project root (script's parent's parent)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
Set-Location $ProjectRoot

# Use UTF-8 output
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
chcp 65001 | Out-Null

# Python interpreter from venv
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    Write-Host "ERROR: Python venv not found at $Python" -ForegroundColor Red
    Write-Host "Please create a venv first: python -m venv .venv"
    exit 1
}

# --- Header -------------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  AutoPenX Verification Suite" -ForegroundColor Cyan
Write-Host "  Project Root: $ProjectRoot" -ForegroundColor DarkGray
Write-Host "  Python:       $Python" -ForegroundColor DarkGray
Write-Host "  Started:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# --- Gate Definitions ---------------------------------------------------------

$Gates = @(
    @{
        Name    = "ruff_lint"
        Command = "$Python -m ruff check autopnex/ --select E,F,W --ignore E501"
    },
    @{
        Name    = "import_check"
        Command = "$Python -c `"import autopnex; import autopnex.agents; import autopnex.evasion`""
    },
    @{
        Name    = "regression"
        Command = "$Python -m pytest tests/test_regression.py -q"
    },
    @{
        Name    = "strict_12"
        Command = "$Python -m pytest tests/benchmark/test_web_benchmark.py -q"
    },
    @{
        Name    = "real_ctf_30"
        Command = "$Python -m pytest tests/benchmark/test_real_ctf.py -m real_ctf -q"
    },
    @{
        Name    = "coverage"
        Command = "__COVERAGE_CHECK__"
    }
)

# --- Gate Execution -----------------------------------------------------------

$Results = @()

foreach ($Gate in $Gates) {
    $GateName = $Gate.Name
    Write-Host "[$GateName] Running..." -ForegroundColor Yellow

    $StartTime = Get-Date

    if ($Gate.Command -eq "__COVERAGE_CHECK__") {
        # Special gate: check that coverage_report.json exists and contains "detailed_coverage"
        $CoverageFile = Join-Path $ProjectRoot "benchmark_results\coverage_report.json"
        if (Test-Path $CoverageFile) {
            $Content = Get-Content $CoverageFile -Raw -ErrorAction SilentlyContinue
            if ($Content -match '"detailed_coverage"') {
                $ExitCode = 0
            } else {
                Write-Host "  Coverage report exists but missing 'detailed_coverage' key" -ForegroundColor Red
                $ExitCode = 1
            }
        } else {
            Write-Host "  Coverage report not found at: $CoverageFile" -ForegroundColor Red
            $ExitCode = 1
        }
    } else {
        # Standard gate: run command and capture exit code
        try {
            Invoke-Expression $Gate.Command 2>&1 | Out-Host
            $ExitCode = $LASTEXITCODE
            if ($null -eq $ExitCode) { $ExitCode = 0 }
        } catch {
            Write-Host "  Error: $_" -ForegroundColor Red
            $ExitCode = 1
        }
    }

    $Duration = (Get-Date) - $StartTime
    $Status = if ($ExitCode -eq 0) { "PASS" } else { "FAIL" }
    $Color = if ($ExitCode -eq 0) { "Green" } else { "Red" }

    Write-Host "[$GateName] $Status ($('{0:N1}' -f $Duration.TotalSeconds)s)" -ForegroundColor $Color
    Write-Host ""

    $Results += @{
        Name     = $GateName
        Status   = $Status
        ExitCode = $ExitCode
        Duration = $Duration
    }
}

# --- Summary Table ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  VERIFICATION SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host ("{0,-20} {1,-10} {2,-10}" -f "Gate", "Status", "Time")
Write-Host ("{0,-20} {1,-10} {2,-10}" -f "----", "------", "----")

$FailCount = 0
foreach ($R in $Results) {
    $Color = if ($R.Status -eq "PASS") { "Green" } else { "Red" }
    $TimeStr = "{0:N1}s" -f $R.Duration.TotalSeconds
    Write-Host ("{0,-20} {1,-10} {2,-10}" -f $R.Name, $R.Status, $TimeStr) -ForegroundColor $Color
    if ($R.Status -eq "FAIL") { $FailCount++ }
}

Write-Host ""
Write-Host "------------------------------------------------------------"

# --- Final Verdict ------------------------------------------------------------

if ($FailCount -eq 0) {
    Write-Host "  VERDICT: ALL PASS ($($Results.Count)/$($Results.Count) gates)" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    exit 0
} else {
    $PassCount = $Results.Count - $FailCount
    Write-Host "  VERDICT: FAILED ($FailCount gate(s) failed, $PassCount/$($Results.Count) passed)" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}
