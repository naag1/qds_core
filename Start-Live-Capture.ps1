#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$python = Join-Path $PSScriptRoot 'venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw 'Project Python environment not found. Create it and install requirements.txt before starting live capture.'
}
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.env'))) {
    throw 'Create the project .env file before starting live capture.'
}

Write-Host 'QDS live capture control is listening at http://127.0.0.1:8765'
Write-Host 'Keep this Administrator PowerShell window open while capturing.'
& $python -m uvicorn app.local_capture:app --host 127.0.0.1 --port 8765
