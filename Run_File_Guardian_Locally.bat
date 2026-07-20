@echo off
setlocal
cd /d "%~dp0"
if not defined FILE_GUARDIAN_LOCAL_WARNING_SHOWN (
  echo Local mode runs document parsing libraries directly on this computer. Use Sandbox mode for stronger isolation when available.
  choice /C YN /M "Continue in local mode"
  if errorlevel 2 exit /b 0
  set "FILE_GUARDIAN_LOCAL_WARNING_SHOWN=1"
)
if not exist ".venv\Scripts\python.exe" (
  echo File Guardian has not been set up yet.
  call Install_and_Run.bat
  exit /b %errorlevel%
)
".venv\Scripts\python.exe" app.py
if errorlevel 1 (
  echo.
  echo File Guardian closed with an error.
  pause
)
