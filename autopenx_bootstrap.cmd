@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

echo ========================================
echo   AutoPenX - Environment Bootstrap
echo ========================================

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] python command not found.
  echo         Install Python 3.10+ and enable "Add Python to PATH".
  echo         Download: https://www.python.org/downloads/
  pause
  exit /b 1
)

if exist ".venv\Scripts\python.exe" (
  echo [1/5] Existing virtual environment detected.
) else (
  echo [1/5] Creating virtual environment...
  python -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Failed to create .venv.
    exit /b 1
  )
)

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv\Scripts\python.exe is missing.
  exit /b 1
)

echo [2/5] Installing core dependencies...
.venv\Scripts\python -m pip install -r requirements.txt --disable-pip-version-check -q
if errorlevel 1 (
  echo [ERROR] Dependency installation failed.
  echo         Check requirements.txt for encoding issues.
  exit /b 1
)

echo [3/5] Installing python-multipart (for file upload)...
.venv\Scripts\python -m pip install python-multipart --disable-pip-version-check -q

echo [4/5] Preparing configuration...
if not exist ".env" (
  if exist ".env.example" (
    copy /y ".env.example" ".env" >nul
    echo       Created .env from template.
  ) else (
    echo       No .env.example found, skipping.
  )
) else (
  echo       Keeping existing .env.
)

echo [5/5] Preparing directories...
if not exist "reports" mkdir reports >nul 2>nul
if not exist "uploads" mkdir uploads >nul 2>nul
if not exist "logs" mkdir logs >nul 2>nul

echo.
echo ========================================
echo   Bootstrap complete!
echo ========================================
exit /b 0
