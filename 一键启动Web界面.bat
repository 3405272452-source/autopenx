@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "PATH=%~dp0external_tools;%PATH%"

echo ========================================
echo   AutoPenX - Web Console
echo ========================================
echo.

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Virtual environment not found.
  echo         Run autopenx_bootstrap.cmd first.
  pause
  exit /b 1
)

echo [1/2] Starting uvicorn on http://127.0.0.1:8000 ...
echo.

set PYTHONUNBUFFERED=1
set "PATH=%~dp0external_tools;%PATH%"
start "AutoPenX Web" cmd /k "set PATH=%~dp0external_tools;%PATH% && cd /d %CD% && .venv\Scripts\python.exe -u -m uvicorn autopnex.web.api:app --host 127.0.0.1 --port 8000 --log-level info"

echo       Waiting for server to start...
timeout /t 4 /nobreak >nul

echo [2/2] Opening browser...
start http://127.0.0.1:8000/

echo.
echo ========================================
echo   Server is running in "AutoPenX Web" window.
echo   Close that window to stop the server.
echo ========================================
echo.
pause
exit /b 0
