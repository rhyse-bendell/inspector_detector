[CmdletBinding()]
param([string]$InputPath, [switch]$GenerateOnly, [string]$OutputWsbPath)
$ErrorActionPreference = 'Stop'
function Resolve-ExistingDirectory([string]$PathValue) {
  if (-not $PathValue) { throw 'No input folder was selected.' }
  $item = Get-Item -LiteralPath $PathValue -ErrorAction Stop
  if (-not $item.PSIsContainer) { throw 'The sandbox input must be a folder.' }
  return $item.FullName
}
function Add-TextElement($doc, $parent, [string]$name, [string]$text) { $e=$doc.CreateElement($name); $e.InnerText=$text; [void]$parent.AppendChild($e); return $e }
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$runtime = Join-Path $repo 'dist\FileGuardian'
$exe = Join-Path $runtime 'FileGuardian.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "Missing packaged runtime: $exe. Run Build_Sandbox_Runtime.bat first." }
if (-not $InputPath) {
  Add-Type -AssemblyName System.Windows.Forms
  $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
  $dialog.Description = 'Select one folder to inspect in Windows Sandbox. The folder is mapped read-only.'
  if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { throw 'No folder selected.' }
  $InputPath = $dialog.SelectedPath
}
$inputFull = Resolve-ExistingDirectory $InputPath
$runtimeFull = (Get-Item -LiteralPath $runtime).FullName
$local = [Environment]::GetFolderPath('LocalApplicationData')
$state = Join-Path $local 'FileGuardian\State'
$runId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([Guid]::NewGuid().ToString('N').Substring(0,8))
$output = Join-Path $local (Join-Path 'FileGuardian\Runs' $runId)
foreach ($dir in @($state, $output)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
foreach ($blocked in @($state, $runtimeFull)) { if ($inputFull.TrimEnd('\') -ieq $blocked.TrimEnd('\')) { throw 'Input folder cannot be the File Guardian runtime, output, or state directory.' } }
$doc = New-Object System.Xml.XmlDocument
$config = $doc.CreateElement('Configuration'); [void]$doc.AppendChild($config)
foreach ($pair in @(@('VGpu','Disable'),@('Networking','Disable'),@('ProtectedClient','Enable'),@('AudioInput','Disable'),@('VideoInput','Disable'),@('PrinterRedirection','Disable'),@('ClipboardRedirection','Disable'),@('MemoryInMB','4096'))) { Add-TextElement $doc $config $pair[0] $pair[1] | Out-Null }
$mapped = $doc.CreateElement('MappedFolders'); [void]$config.AppendChild($mapped)
foreach ($m in @(@($runtimeFull,'C:\FileGuardian\Runtime','true'),@($inputFull,'C:\FileGuardian\Input','true'),@($output,'C:\FileGuardian\Output','false'),@($state,'C:\FileGuardian\State','false'))) { $mf=$doc.CreateElement('MappedFolder'); [void]$mapped.AppendChild($mf); Add-TextElement $doc $mf 'HostFolder' $m[0] | Out-Null; Add-TextElement $doc $mf 'SandboxFolder' $m[1] | Out-Null; Add-TextElement $doc $mf 'ReadOnly' $m[2] | Out-Null }
$logon=$doc.CreateElement('LogonCommand'); [void]$config.AppendChild($logon); Add-TextElement $doc $logon 'Command' 'C:\FileGuardian\Runtime\Start-FileGuardianInSandbox.ps1' | Out-Null
if (-not $OutputWsbPath) { $OutputWsbPath = Join-Path ([IO.Path]::GetTempPath()) ("FileGuardian-$runId.wsb") }
try { $settings=New-Object System.Xml.XmlWriterSettings; $settings.Indent=$true; $settings.Encoding=[Text.UTF8Encoding]::new($false); $writer=[System.Xml.XmlWriter]::Create($OutputWsbPath,$settings); $doc.Save($writer); $writer.Close(); Write-Host "WSB: $OutputWsbPath"; Write-Host "Output: $output"; if ($GenerateOnly) { return }; $p=Start-Process -FilePath $OutputWsbPath -Wait -PassThru; Write-Host "Sandbox closed. Output directory: $output"; if ((Read-Host 'Open output folder in Explorer? [y/N]') -match '^[Yy]') { Start-Process explorer.exe -ArgumentList @($output) }; exit $p.ExitCode } finally { if (-not $GenerateOnly -and (Test-Path -LiteralPath $OutputWsbPath)) { Remove-Item -LiteralPath $OutputWsbPath -Force -ErrorAction SilentlyContinue } }
