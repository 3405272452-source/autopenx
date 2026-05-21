@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

call "%~dp0autopenx_bootstrap.cmd"
set "EXIT_CODE=%errorlevel%"

echo.
if "%EXIT_CODE%"=="0" (
  echo ========================================
  echo AutoPenX environment is ready.
  echo Launch the Web UI or CLI scanner next.
  echo A valid DEEPSEEK_API_KEY in .env enables real LLM mode.
  echo ========================================
) else (
  echo ========================================
  echo AutoPenX setup failed.
  echo Check the error messages above and retry.
  echo ========================================
)
pause
exit /b %EXIT_CODE%
