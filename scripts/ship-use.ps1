#Requires -Version 5
# Compile the use worktree in a process outside Luvus, then overwrite the daily install.
# Never run `cargo` inside a Luvus pane — that session gets killed mid-build.
# Never auto-start Luvus. To open: Windows Terminal, cwd = use wt.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/ship-use.ps1
# Detached:
#   cmd /c start "ship-use" powershell -NoProfile -ExecutionPolicy Bypass -File <this>
# Open (manual):
#   wt.exe -d F:\Project\luvus\.worktrees\use -- F:\CodexData\luvus-use-target\release\luvus.exe
$ErrorActionPreference = 'Stop'
$Use = 'F:\Project\luvus\.worktrees\use'
$Target = 'F:\CodexData\luvus-use-target'
$Dest = 'F:\Apps\Luvus\luvus.exe'
$LogDir = Join-Path $Target 'logs'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$Log = Join-Path $LogDir ('ship-use-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
function Write-Log([string]$Message) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message
    Add-Content -LiteralPath $Log -Value $line
    Write-Host $line
}
Write-Log "use=$Use"
Write-Log "target=$Target"
Write-Log "log=$Log"
$env:CARGO_TARGET_DIR = $Target
Set-Location -LiteralPath $Use
Write-Log 'cargo build --release'
& cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Log "cargo failed $LASTEXITCODE"
    exit $LASTEXITCODE
}
$src = Join-Path $Target 'release\luvus.exe'
if (-not (Test-Path -LiteralPath $src)) {
    Write-Log "missing $src"
    exit 1
}
Write-Log 'stop luvus (unlock install exe)'
Get-Process -Name luvus -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
Write-Log "copy -> $Dest"
Copy-Item -LiteralPath $src -Destination $Dest -Force
$srcItem = Get-Item -LiteralPath $src
$dstItem = Get-Item -LiteralPath $Dest
Write-Log ('src={0} {1}' -f $srcItem.Length, $srcItem.LastWriteTime)
Write-Log ('dst={0} {1}' -f $dstItem.Length, $dstItem.LastWriteTime)
if ($srcItem.Length -ne $dstItem.Length) {
    Write-Log 'size mismatch'
    exit 2
}
Write-Log 'done (no auto-start; open with wt.exe -d use wt)'
