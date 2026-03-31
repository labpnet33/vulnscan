param(
  [string]$ClientId = "",
  [string]$Token = "",
  [string]$ServerUrl = "http://161.118.189.254:5000"
)

$ErrorActionPreference = "Stop"

function Write-Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok($m) { Write-Host "[+] $m" -ForegroundColor Green }
function Write-Err($m) { Write-Host "[x] $m" -ForegroundColor Red }

Write-Info "Preparing VulnScan Lynis agent install for Windows host"
Write-Info "This installer runs the Linux agent through WSL (required by Lynis)."

$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wsl) {
  Write-Err "WSL is not installed. Install WSL first: wsl --install"
  exit 1
}

if ([string]::IsNullOrWhiteSpace($ClientId)) {
  $hostname = $env:COMPUTERNAME
  $rand = -join ((48..57) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_})
  $ClientId = "$hostname-$rand".ToLower()
  Write-Info "Generated client id: $ClientId"
}

Write-Info "Testing server connectivity: $ServerUrl"
try {
  Invoke-WebRequest -UseBasicParsing -Uri "$ServerUrl/health" -TimeoutSec 15 | Out-Null
  Write-Ok "Connected to VulnScan server"
}
catch {
  Write-Err "Cannot reach server: $($_.Exception.Message)"
  exit 1
}

$cmd = "curl -fsSL '$ServerUrl/agent/install.sh' | bash -s -- '$ClientId' '$Token' '$ServerUrl'"
Write-Info "Running Linux installer in WSL..."
wsl.exe bash -lc $cmd

if ($LASTEXITCODE -ne 0) {
  Write-Err "WSL install command failed."
  exit $LASTEXITCODE
}

Write-Ok "Agent install command completed in WSL."
Write-Host "Refresh the Lynis page and check Connected Agent Systems."
