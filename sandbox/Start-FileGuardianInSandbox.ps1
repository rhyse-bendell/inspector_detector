Set-StrictMode -Version Latest
$SandboxFeatureName = 'Containers-DisposableClientVM'
function Test-FileGuardianSandboxPrerequisites {
    param([string]$RepositoryRoot, [string]$RuntimePath, [switch]$SkipHostChecks)
    $problems = New-Object System.Collections.Generic.List[string]
    $exePath = Join-Path $RuntimePath 'FileGuardian.exe'
    if (-not (Test-Path -LiteralPath $exePath)) { $problems.Add("Packaged runtime is missing. Run Build_Sandbox_Runtime.bat first.") }
    else {
        $exeTime = (Get-Item -LiteralPath $exePath).LastWriteTimeUtc
        foreach ($source in @((Join-Path $RepositoryRoot 'app.py'), (Join-Path $RepositoryRoot 'file_guardian.py'), (Join-Path $RepositoryRoot 'requirements.txt'))) {
            if ((Test-Path -LiteralPath $source) -and (Get-Item -LiteralPath $source).LastWriteTimeUtc -gt $exeTime) { $problems.Add("Packaged runtime is older than source or requirements. Re-run Build_Sandbox_Runtime.bat."); break }
        }
    }
    if (-not $SkipHostChecks) {
        $edition = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).OperatingSystemSKU
        if ($edition -in @(100,101,123,125)) { $problems.Add('This Windows edition may not support Windows Sandbox.') }
        $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cpu -and -not $cpu.VirtualizationFirmwareEnabled) { $problems.Add('Firmware virtualization is disabled.') }
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $SandboxFeatureName -ErrorAction SilentlyContinue
        if (-not $feature -or $feature.State -ne 'Enabled') { $problems.Add('Windows Sandbox optional feature is not enabled.') }
    }
    [pscustomobject]@{ Available = ($problems.Count -eq 0); Problems = @($problems) }
}
function Add-ElementText($doc, $parent, [string]$name, [string]$text) { $e=$doc.CreateElement($name); $e.InnerText=$text; [void]$parent.AppendChild($e); return $e }
function New-FileGuardianSandboxConfig {
    param([string]$RepositoryRoot,[string]$RuntimePath,[string]$InputFolder,[string]$OutputRoot,[string]$StateFolder,[int]$MemoryInMB = 2048)
    if ($MemoryInMB -lt 2048) { throw 'Sandbox memory must be at least 2048 MB.' }
    foreach ($p in @($RuntimePath,$InputFolder)) { if (-not (Test-Path -LiteralPath $p)) { throw "Path does not exist: $p" } }
    $local = Join-Path $env:LOCALAPPDATA 'FileGuardian'
    if (-not $OutputRoot) { $OutputRoot = Join-Path $local (Join-Path 'Runs' ([guid]::NewGuid().ToString('N'))) }
    if (-not $StateFolder) { $StateFolder = Join-Path $local 'State' }
    New-Item -ItemType Directory -Path $OutputRoot,$StateFolder -Force | Out-Null
    $doc = New-Object System.Xml.XmlDocument
    $root = $doc.CreateElement('Configuration'); [void]$doc.AppendChild($root)
    foreach ($kv in @(@('VGpu','Disable'),@('Networking','Disable'),@('ProtectedClient','Enable'),@('AudioInput','Disable'),@('VideoInput','Disable'),@('PrinterRedirection','Disable'),@('ClipboardRedirection','Disable'),@('MemoryInMB',[string]$MemoryInMB))) { Add-ElementText $doc $root $kv[0] $kv[1] | Out-Null }
    $mapped = $doc.CreateElement('MappedFolders'); [void]$root.AppendChild($mapped)
    foreach ($m in @(@($RuntimePath,'C:\FileGuardian\Runtime','true'),@($InputFolder,'C:\FileGuardian\Input','true'),@($OutputRoot,'C:\FileGuardian\Output','false'),@($StateFolder,'C:\FileGuardian\State','false'))) {
        $mf=$doc.CreateElement('MappedFolder'); [void]$mapped.AppendChild($mf); Add-ElementText $doc $mf 'HostFolder' $m[0] | Out-Null; Add-ElementText $doc $mf 'SandboxFolder' $m[1] | Out-Null; Add-ElementText $doc $mf 'ReadOnly' $m[2] | Out-Null
    }
    $logon = $doc.CreateElement('LogonCommand'); [void]$root.AppendChild($logon)
    Add-ElementText $doc $logon 'Command' 'C:\FileGuardian\Runtime\FileGuardian.exe C:\FileGuardian\Input --recursive --gui --json C:\FileGuardian\Output\file_guardian_report.json --csv C:\FileGuardian\Output\file_guardian_report.csv --tag-store C:\FileGuardian\State\tags.json --execution-environment windows-sandbox' | Out-Null
    $path = Join-Path $OutputRoot 'FileGuardianSandbox.wsb'; $doc.Save($path)
    [pscustomobject]@{ ConfigPath=$path; OutputRoot=$OutputRoot; StateFolder=$StateFolder }
}
