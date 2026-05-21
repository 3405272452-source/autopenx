@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

call "%~dp0autopenx_bootstrap.cmd"
if errorlevel 1 (
  echo.
  echo [ERROR] Bootstrap failed. Scan was not started.
  pause
  exit /b 1
)

set "DEEPSEEK_KEY="
if exist ".env" (
  for /f "usebackq tokens=1,* delims==" %%A in (`findstr /b /c:"DEEPSEEK_API_KEY=" ".env"`) do set "DEEPSEEK_KEY=%%B"
)

set "SCAN_MODE=--mock"
set "MODE_LABEL=offline mock mode"
if defined DEEPSEEK_KEY (
  set "SCAN_MODE="
  set "MODE_LABEL=DeepSeek LLM mode"
)

set /p TARGET=Enter target URL (for example http://testphp.vulnweb.com): 
if "%TARGET%"=="" (
  echo Target is required.
  pause
  exit /b 1
)

echo.
echo ========================================
echo Running scan for %TARGET% in %MODE_LABEL%...
echo Reports will be written to the reports directory.
if defined DEEPSEEK_KEY (
  echo Detected DEEPSEEK_API_KEY in .env.
) else (
  echo No valid DEEPSEEK_API_KEY detected, falling back to --mock.
)
echo ========================================
echo.
.venv\Scripts\python autopnex.py --target "%TARGET%" %SCAN_MODE% --yes --out reports\scan.md --html reports\scan.html
set "EXIT_CODE=%errorlevel%"

echo.
if not "%EXIT_CODE%"=="0" (
  echo [ERROR] Scan exited unexpectedly.
) else (
  echo [INFO] Scan finished. Reports are available in reports\scan.md and reports\scan.html
)
pause
exit /b %EXIT_CODE%
