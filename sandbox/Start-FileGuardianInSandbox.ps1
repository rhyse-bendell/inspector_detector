$ErrorActionPreference = 'Stop'
$env:FILE_GUARDIAN_EXECUTION_ENVIRONMENT = 'windows-sandbox'
$runtime = 'C:\FileGuardian\Runtime\FileGuardian.exe'
$inputDir = 'C:\FileGuardian\Input'
$outputDir = 'C:\FileGuardian\Output'
$stateDir = 'C:\FileGuardian\State'
$failureLog = Join-Path $outputDir 'file_guardian_startup_failure.txt'
try {
  foreach ($path in @($runtime, $inputDir, $outputDir, $stateDir)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required sandbox path is missing: $path" }
  }
  $args = @($inputDir, '--recursive', '--gui', '--json', (Join-Path $outputDir 'file_guardian_report.json'), '--csv', (Join-Path $outputDir 'file_guardian_report.csv'), '--tag-store', (Join-Path $stateDir 'tags.json'))
  $p = Start-Process -FilePath $runtime -ArgumentList $args -Wait -PassThru
  exit $p.ExitCode
} catch {
  try { New-Item -ItemType Directory -Force -Path $outputDir | Out-Null; $_ | Out-String | Set-Content -LiteralPath $failureLog -Encoding UTF8 } catch {}
  exit 1
}
