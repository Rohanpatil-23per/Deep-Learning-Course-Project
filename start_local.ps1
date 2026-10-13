param([switch]$Build)

$ErrorActionPreference = 'Stop'
$env:KMP_DUPLICATE_LIB_OK = 'TRUE'
$env:OMP_NUM_THREADS = '1'
$env:PYTHONUTF8 = '1'
$root = $PSScriptRoot
$frontend = Join-Path $root 'IMMUNEX\immunex_wired\immunex_wired'
$python = 'F:\anaconda3\python.exe'
if (-not (Test-Path $python)) { $python = 'python' }

$existing = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($existing) {
  $owner = ($existing | Select-Object -First 1).OwningProcess
  Write-Host "Port 8000 is already in use by process $owner."
  Write-Host 'Close that app or run .\stop_local.ps1, then start IMMUNEX again.'
  exit 1
}

if ($Build -or -not (Test-Path (Join-Path $frontend 'dist\index.html'))) {
  Push-Location $frontend
  try {
    if (-not (Test-Path 'node_modules')) { npm ci --cache .npm-cache }
    npm run build
  } finally { Pop-Location }
}

Write-Host 'IMMUNEX is ready at http://127.0.0.1:8000'
Set-Location $root
& $python -m uvicorn local_runtime:app --host 127.0.0.1 --port 8000
