@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo.
echo   AutoPenX - Environment Dependency Checker
echo.

if exist ".venv\Scripts\python.exe" (
  .venv\Scripts\python check_environment.py %*
) else (
  where python >nul 2>nul
  if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ first.
    echo         https://www.python.org/downloads/
  ) else (
    python check_environment.py %*
  )
)

echo.
pause
