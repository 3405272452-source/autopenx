@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ========================================
echo   AutoPenX - External Tools Installer
echo ========================================
echo.

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Virtual environment not found.
  echo         Run "一键安装依赖.bat" first.
  pause
  exit /b 1
)

.venv\Scripts\python install_external_tools.py

echo.
pause
