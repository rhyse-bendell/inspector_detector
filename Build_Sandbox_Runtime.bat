@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PYTHON_CMD="
where py >nul 2>&1 && set "PYTHON_CMD=py -3"
if not defined PYTHON_CMD where python >nul 2>&1 && set "PYTHON_CMD=python"
if not defined PYTHON_CMD (
  echo Python 3 was not found. Install 64-bit Python 3 and try again.
  exit /b 1
)

if not exist ".build-venv\Scripts\python.exe" (
  %PYTHON_CMD% -m venv .build-venv || exit /b 1
)
".build-venv\Scripts\python.exe" -m pip install --upgrade pip || exit /b 1
".build-venv\Scripts\python.exe" -m pip install -r requirements.txt -r requirements-build.txt || exit /b 1
".build-venv\Scripts\python.exe" -m pytest || exit /b 1
".build-venv\Scripts\pyinstaller.exe" --clean --noconfirm file_guardian.spec || exit /b 1
if not exist "dist\FileGuardian\FileGuardian.exe" (
  echo Packaged runtime was not created at dist\FileGuardian\FileGuardian.exe.
  exit /b 1
)
"dist\FileGuardian\FileGuardian.exe" --version || exit /b 1
echo File Guardian sandbox runtime built successfully at dist\FileGuardian\FileGuardian.exe.
exit /b 0
