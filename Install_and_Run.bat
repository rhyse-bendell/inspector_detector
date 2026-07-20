@echo off
setlocal
cd /d "%~dp0"

echo File Guardian setup
 echo -------------------

set "PYTHON_CMD="
where py >nul 2>&1
if %errorlevel%==0 set "PYTHON_CMD=py -3"
if not defined PYTHON_CMD (
    where python >nul 2>&1
    if %errorlevel%==0 set "PYTHON_CMD=python"
)

if not defined PYTHON_CMD (
    echo.
    echo Python 3 was not found.
    echo Install a current 64-bit Python 3 release, enable Add Python to PATH,
    echo then run this file again.
    echo.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating isolated Python environment...
    %PYTHON_CMD% -m venv .venv
    if errorlevel 1 goto :failure
)

echo Updating pip...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :failure

echo Installing File Guardian parsing libraries...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo Dependency installation failed. File Guardian can still run with reduced capability.
    echo PDF, image metadata, or VBA source-level analysis may be unavailable.
    echo.
    pause
)

echo Launching File Guardian...
".venv\Scripts\python.exe" app.py
exit /b %errorlevel%

:failure
echo.
echo Setup failed. Review the error above.
pause
exit /b 1
