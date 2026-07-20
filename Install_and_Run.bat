@echo off
setlocal EnableExtensions
cd /d "%~dp0"
echo File Guardian first-run setup for Windows Sandbox
echo ------------------------------------------------
set "ENABLE_CMD=Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All"
for /f "tokens=4-5 delims=. " %%i in ('ver') do set VERSION=%%i.%%j
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$os=Get-CimInstance Win32_OperatingSystem; if ($os.Caption -match ' Home') { Write-Error 'Windows Sandbox is not supported on Windows Home. Use Pro, Enterprise, or Education.'; exit 10 }; $cpu=Get-CimInstance Win32_Processor | Select-Object -First 1; if (-not $cpu.VirtualizationFirmwareEnabled) { Write-Error 'Hardware virtualization is unavailable or disabled in firmware.'; exit 11 }; $f=Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction SilentlyContinue; if (-not $f -or $f.State -ne 'Enabled') { Write-Error 'Windows Sandbox feature is disabled. In an elevated PowerShell run: Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All then restart.'; exit 12 }"
if errorlevel 1 (
  echo.
  echo Windows Sandbox is not ready. Do not run File Guardian locally unless you intentionally choose Run_File_Guardian_Locally.bat.
  echo Elevated enablement command:
  echo Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All
  echo Restart Windows after enabling the feature.
  exit /b 1
)
call Build_Sandbox_Runtime.bat || exit /b 1
if not exist "dist\FileGuardian\FileGuardian.exe" (
  echo Packaged runtime missing after build.
  exit /b 1
)
call Run_File_Guardian.bat
exit /b %errorlevel%
