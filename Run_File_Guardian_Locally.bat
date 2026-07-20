@echo off
setlocal
cd /d "%~dp0"
echo WARNING: Less-isolated local fallback.
echo Document parsers will run directly on this Windows host, not inside Windows Sandbox.
echo Use this only for development or troubleshooting with files you are authorized to inspect.
set /p CONFIRM="Type RUNLOCAL to continue: "
if not "%CONFIRM%"=="RUNLOCAL" exit /b 1
if not exist ".venv\Scripts\python.exe" call Install_and_Run.bat /setup-only
if errorlevel 1 exit /b 1
".venv\Scripts\python.exe" app.py
exit /b %errorlevel%
