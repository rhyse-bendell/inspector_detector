[CmdletBinding()]
param(
    [switch]$TestMode,
    [string]$SimulatedChoice,
    [switch]$ClearPreference,
    [switch]$NoLaunch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$SettingsPath = Join-Path $env:LOCALAPPDATA 'FileGuardian\launcher-settings.json'
$ValidModes = @('local', 'sandbox')

function Get-FileGuardianLauncherSettings {
    param([string]$Path = $SettingsPath)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $settings = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($settings.version -ne 1) { return $null }
        if ($settings.rememberedMode -notin $ValidModes) { return $null }
        return [pscustomobject]@{ Version = 1; RememberedMode = [string]$settings.rememberedMode }
    } catch { return $null }
}

function Save-FileGuardianLauncherPreference {
    param([ValidateSet('local','sandbox')] [string]$Mode, [string]$Path = $SettingsPath)
    $dir = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    [pscustomobject]@{ version = 1; rememberedMode = $Mode } | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Clear-FileGuardianLauncherPreference {
    param([string]$Path = $SettingsPath)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
}

function Show-FileGuardianModeDialog {
    param([string]$DefaultMode = 'local')
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object Windows.Forms.Form
    $form.Text = 'File Guardian execution mode'
    $form.Width = 560; $form.Height = 300; $form.StartPosition = 'CenterScreen'
    $local = New-Object Windows.Forms.RadioButton
    $local.Text = 'Run locally - Runs directly on this computer. Available now.'
    $local.Left = 20; $local.Top = 25; $local.Width = 500; $local.Checked = ($DefaultMode -eq 'local')
    $sandbox = New-Object Windows.Forms.RadioButton
    $sandbox.Text = 'Run in Windows Sandbox - Runs in a disposable Windows environment with the input folder mounted read-only. Requires supported Windows, firmware virtualization, and Windows Sandbox.'
    $sandbox.Left = 20; $sandbox.Top = 65; $sandbox.Width = 500; $sandbox.Height = 55; $sandbox.Checked = ($DefaultMode -eq 'sandbox')
    $remember = New-Object Windows.Forms.CheckBox
    $remember.Text = 'Remember my choice'; $remember.Left = 20; $remember.Top = 135; $remember.Width = 220
    $clear = New-Object Windows.Forms.Button
    $clear.Text = 'Forget saved choice'; $clear.Left = 20; $clear.Top = 175; $clear.Width = 150
    $ok = New-Object Windows.Forms.Button
    $ok.Text = 'Continue'; $ok.Left = 280; $ok.Top = 220; $ok.Width = 100; $ok.DialogResult = [Windows.Forms.DialogResult]::OK
    $cancel = New-Object Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.Left = 400; $cancel.Top = 220; $cancel.Width = 100; $cancel.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $clear.Add_Click({ Clear-FileGuardianLauncherPreference; [Windows.Forms.MessageBox]::Show('Saved File Guardian launcher preference cleared.','File Guardian') | Out-Null })
    $form.Controls.AddRange(@($local,$sandbox,$remember,$clear,$ok,$cancel)); $form.AcceptButton=$ok; $form.CancelButton=$cancel
    if ($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { return [pscustomobject]@{ Action='cancel' } }
    return [pscustomobject]@{ Action='run'; Mode = $(if ($sandbox.Checked) {'sandbox'} else {'local'}); Remember = [bool]$remember.Checked }
}

function Resolve-FileGuardianMode {
    param([string]$Choice, [string]$SettingsPath = $SettingsPath)
    if ($ClearPreference) { Clear-FileGuardianLauncherPreference -Path $SettingsPath }
    $settings = Get-FileGuardianLauncherSettings -Path $SettingsPath
    if ($Choice) { return [pscustomobject]@{ Action='run'; Mode=$Choice; Remember=$false; Source='choice' } }
    if ($settings) { return [pscustomobject]@{ Action='run'; Mode=$settings.RememberedMode; Remember=$false; Source='remembered' } }
    if ($TestMode) { return [pscustomobject]@{ Action='run'; Mode='local'; Remember=$false; Source='default' } }
    $selection = Show-FileGuardianModeDialog -DefaultMode 'local'
    $selection | Add-Member -NotePropertyName Source -NotePropertyValue 'chooser'
    return $selection
}

function Start-FileGuardianLocal { param([string]$Root = $RepoRoot) & (Join-Path $Root 'Run_File_Guardian_Locally.bat') }
function Start-FileGuardianSandbox { param([string]$Root = $RepoRoot) & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'sandbox\Launch-FileGuardianSandbox.ps1') -RepositoryRoot $Root }

if ($MyInvocation.InvocationName -ne '.') {
    Set-Location -LiteralPath $RepoRoot
    $selection = Resolve-FileGuardianMode -Choice $SimulatedChoice
    if ($selection.Action -eq 'cancel') { exit 0 }
    if ($selection.Remember) { Save-FileGuardianLauncherPreference -Mode $selection.Mode }
    if ($NoLaunch -or $TestMode) { $selection | ConvertTo-Json -Compress; exit 0 }
    if ($selection.Mode -eq 'sandbox') { Start-FileGuardianSandbox } else { Start-FileGuardianLocal }
}
