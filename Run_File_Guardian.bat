@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo File Guardian has not been set up yet.
    echo Starting first-run setup...
    call Install_and_Run.bat
    exit /b %errorlevel%
)

".venv\Scripts\python.exe" app.py
if errorlevel 1 (
    echo.
    echo File Guardian closed with an error.
    pause
)
