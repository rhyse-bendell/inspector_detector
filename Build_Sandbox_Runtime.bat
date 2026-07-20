@echo off
setlocal
cd /d "%~dp0"
set "PYTHON_CMD="
where py >nul 2>&1 && set "PYTHON_CMD=py -3"
if not defined PYTHON_CMD where python >nul 2>&1 && set "PYTHON_CMD=python"
if not defined PYTHON_CMD exit /b 1
if not exist ".build-venv\Scripts\python.exe" %PYTHON_CMD% -m venv .build-venv || exit /b 1
".build-venv\Scripts\python.exe" -m pip install --upgrade pip || exit /b 1
".build-venv\Scripts\python.exe" -m pip install -r requirements.txt -r requirements-build.txt || exit /b 1
".build-venv\Scripts\python.exe" -m unittest discover -s tests -v || exit /b 1
".build-venv\Scripts\pyinstaller.exe" --noconfirm file_guardian.spec || exit /b 1
"dist\FileGuardian\FileGuardian.exe" --version || exit /b 1
