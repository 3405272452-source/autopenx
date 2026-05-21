@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ========================================
echo   AutoPenX - One-Click Setup
echo ========================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found!
  echo.
  echo Please install Python 3.10+ from:
  echo   https://www.python.org/downloads/
  echo.
  echo IMPORTANT: Check "Add Python to PATH" during installation!
  echo.
  pause
  exit /b 1
)

echo [Step 1/4] Running bootstrap (venv + pip packages)...
call "%~dp0autopenx_bootstrap.cmd"
if errorlevel 1 (
  echo.
  echo [ERROR] Bootstrap failed. See errors above.
  pause
  exit /b 1
)

echo.
echo [Step 2/4] Installing Playwright browser (for login helper)...
if exist ".venv\Scripts\playwright.exe" (
  .venv\Scripts\playwright install chromium
) else (
  echo   Playwright not available, skipping browser install.
)

echo.
echo [Step 3/4] Running environment check...
.venv\Scripts\python check_environment.py

echo.
echo [Step 4/4] Done!
echo.
echo ========================================
echo   Setup complete! You can now run:
echo   - "一键启动Web界面.bat" to start the web UI
echo   - "检查环境依赖.bat" to re-check dependencies
echo ========================================
echo.
pause
