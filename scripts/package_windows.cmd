@echo off
REM ============================================================================
REM CET4 Study App — Windows packaging script
REM Builds a single-file EXE using PyInstaller with build/pyinstaller.spec
REM Output: dist/CET4StudyApp.exe
REM ============================================================================

setlocal enabledelayedexpansion

echo ============================================
echo  CET4 Study App — Windows Packager
echo ============================================
echo.

REM Navigate to project root (one level up from scripts/)
cd /d "%~dp0.."
set "PROJECT_ROOT=%cd%"
echo Project root: %PROJECT_ROOT%
echo.

REM Activate virtual environment if present
if exist "%PROJECT_ROOT%\.venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call "%PROJECT_ROOT%\.venv\Scripts\activate.bat"
    echo Virtual environment activated.
) else if exist "%PROJECT_ROOT%\venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call "%PROJECT_ROOT%\venv\Scripts\activate.bat"
    echo Virtual environment activated.
) else (
    echo WARNING: No virtual environment found. Using system Python.
)
echo.

REM Check that PyInstaller is available
where pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: PyInstaller is not installed.
    echo Install it with: pip install pyinstaller
    exit /b 1
)

REM Check that the spec file exists
if not exist "%PROJECT_ROOT%\build\pyinstaller.spec" (
    echo ERROR: build\pyinstaller.spec not found.
    exit /b 1
)

REM Clean previous build artifacts
echo Cleaning previous build artifacts...
if exist "%PROJECT_ROOT%\dist\CET4StudyApp.exe" del /f "%PROJECT_ROOT%\dist\CET4StudyApp.exe"
echo.

REM Run PyInstaller
echo Running PyInstaller...
echo.
pyinstaller --clean --noconfirm "%PROJECT_ROOT%\build\pyinstaller.spec" --distpath "%PROJECT_ROOT%\dist" --workpath "%PROJECT_ROOT%\build\pyinstaller_work"

if %errorlevel% neq 0 (
    echo.
    echo ============================================
    echo  BUILD FAILED
    echo ============================================
    echo Check the output above for errors.
    exit /b 1
)

echo.
echo ============================================
echo  BUILD SUCCESSFUL
echo ============================================
echo.
echo Output: %PROJECT_ROOT%\dist\CET4StudyApp.exe
echo.

REM Verify the EXE was created
if exist "%PROJECT_ROOT%\dist\CET4StudyApp.exe" (
    for %%A in ("%PROJECT_ROOT%\dist\CET4StudyApp.exe") do (
        echo File size: %%~zA bytes
    )
) else (
    echo WARNING: EXE file not found at expected location.
    exit /b 1
)

endlocal
exit /b 0
