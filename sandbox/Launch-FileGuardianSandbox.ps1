[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$InputFolder,
    [string]$OutputRoot,
    [string]$StateFolder,
    [int]$MemoryInMB = 2048,
    [switch]$GenerateOnly,
    [switch]$AssumePrerequisites
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Start-FileGuardianInSandbox.ps1')

if (-not $InputFolder) {
    if ($GenerateOnly) { throw 'InputFolder is required in GenerateOnly mode.' }
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Select the folder to inspect read-only inside Windows Sandbox.'
    if ($dialog.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { exit 0 }
    $InputFolder = $dialog.SelectedPath
}

$runtime = Join-Path $RepositoryRoot 'dist\FileGuardian'
$pre = Test-FileGuardianSandboxPrerequisites -RepositoryRoot $RepositoryRoot -RuntimePath $runtime -SkipHostChecks:$AssumePrerequisites
if (-not $pre.Available) {
    $msg = ($pre.Problems -join "`n") + "`n`nFile Guardian will not change Windows settings automatically. To install Windows Sandbox on supported editions, run as administrator:`nEnable-WindowsOptionalFeature -Online -FeatureName \"Containers-DisposableClientVM\" -All`n`nFirmware virtualization must be enabled separately in BIOS/UEFI when disabled."
    if ($GenerateOnly) { throw $msg }
    Add-Type -AssemblyName System.Windows.Forms
    $choice = [Windows.Forms.MessageBox]::Show($msg + "`n`nClick Yes to run locally instead, No to return to mode selection, or Cancel to exit.", 'Windows Sandbox unavailable', 'YesNoCancel', 'Warning')
    if ($choice -eq [Windows.Forms.DialogResult]::Yes) { & (Join-Path $RepositoryRoot 'Run_File_Guardian_Locally.bat') }
    elseif ($choice -eq [Windows.Forms.DialogResult]::No) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepositoryRoot 'launcher\Launch-FileGuardian.ps1') }
    exit 0
}

$config = New-FileGuardianSandboxConfig -RepositoryRoot $RepositoryRoot -RuntimePath $runtime -InputFolder $InputFolder -OutputRoot $OutputRoot -StateFolder $StateFolder -MemoryInMB $MemoryInMB
if ($GenerateOnly) { $config.ConfigPath; exit 0 }
Start-Process -FilePath $config.ConfigPath
