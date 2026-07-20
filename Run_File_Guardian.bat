@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "RUNTIME_EXE=dist\FileGuardian\FileGuardian.exe"
if not exist "%RUNTIME_EXE%" (
  echo File Guardian sandbox runtime is missing.
  echo Run Build_Sandbox_Runtime.bat to create dist\FileGuardian\FileGuardian.exe.
  set /p BUILD_NOW="Build it now? [y/N] "
  if /i "%BUILD_NOW%"=="Y" call Build_Sandbox_Runtime.bat
  if errorlevel 1 exit /b 1
  if not exist "%RUNTIME_EXE%" exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$exe=(Get-Item -LiteralPath 'dist\FileGuardian\FileGuardian.exe'); $sources=@('app.py','file_guardian.py','requirements.txt','file_guardian.spec','sandbox\Start-FileGuardianInSandbox.ps1','sandbox\Launch-FileGuardianSandbox.ps1'); foreach($s in $sources){ if((Get-Item -LiteralPath $s).LastWriteTimeUtc -gt $exe.LastWriteTimeUtc){ Write-Error "Packaged runtime may be stale because $s is newer than dist\FileGuardian\FileGuardian.exe. Re-run Build_Sandbox_Runtime.bat."; exit 1 }}"
if errorlevel 1 exit /b 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0sandbox\Launch-FileGuardianSandbox.ps1"
exit /b %errorlevel%
