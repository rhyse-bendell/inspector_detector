BeforeAll {
  . "$PSScriptRoot\..\..\launcher\Launch-FileGuardian.ps1"
  . "$PSScriptRoot\..\..\sandbox\Start-FileGuardianInSandbox.ps1"
}
Describe 'File Guardian launcher settings' {
  It 'defaults first launch to local mode' {
    $dir = Join-Path $TestDrive 'FileGuardian'; New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $result = Resolve-FileGuardianMode -SettingsPath (Join-Path $dir 'missing.json')
    $result.Mode | Should -Be 'local'
  }
  It 'respects remembered local preference' {
    $path = Join-Path $TestDrive 'settings.json'; Save-FileGuardianLauncherPreference -Mode local -Path $path
    (Resolve-FileGuardianMode -SettingsPath $path).Mode | Should -Be 'local'
  }
  It 'respects remembered sandbox preference' {
    $path = Join-Path $TestDrive 'settings2.json'; Save-FileGuardianLauncherPreference -Mode sandbox -Path $path
    (Resolve-FileGuardianMode -SettingsPath $path).Mode | Should -Be 'sandbox'
  }
  It 'malformed preference returns to default chooser behavior' {
    $path = Join-Path $TestDrive 'bad.json'; Set-Content -Path $path -Value '{nope'
    (Resolve-FileGuardianMode -SettingsPath $path).Mode | Should -Be 'local'
  }
}
Describe 'Sandbox configuration' {
  It 'generates hardened XML and restricted mappings' {
    $runtime = Join-Path $TestDrive 'Runtime'; $input = Join-Path $TestDrive 'Input & <x>'; New-Item -ItemType Directory -Path $runtime,$input -Force | Out-Null; New-Item -ItemType File -Path (Join-Path $runtime 'FileGuardian.exe') | Out-Null
    $cfg = New-FileGuardianSandboxConfig -RepositoryRoot $TestDrive -RuntimePath $runtime -InputFolder $input -MemoryInMB 2048
    [xml]$xml = Get-Content -LiteralPath $cfg.ConfigPath -Raw
    $xml.Configuration.Networking | Should -Be 'Disable'
    $xml.Configuration.ClipboardRedirection | Should -Be 'Disable'
    $xml.Configuration.MappedFolders.MappedFolder[0].ReadOnly | Should -Be 'true'
    $xml.Configuration.MappedFolders.MappedFolder[1].ReadOnly | Should -Be 'true'
    $xml.Configuration.MappedFolders.MappedFolder.Count | Should -Be 4
  }
  It 'rejects memory below 2048 MB' {
    { New-FileGuardianSandboxConfig -RepositoryRoot $TestDrive -RuntimePath $TestDrive -InputFolder $TestDrive -MemoryInMB 1024 } | Should -Throw
  }
  It 'does not report prerequisites available without a packaged runtime' {
    (Test-FileGuardianSandboxPrerequisites -RepositoryRoot $TestDrive -RuntimePath (Join-Path $TestDrive 'missing') -SkipHostChecks).Available | Should -BeFalse
  }
}
