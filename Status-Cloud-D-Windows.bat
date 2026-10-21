@echo off
setlocal
cd /d "%~dp0"

echo Checking Cloud-D status...
powershell -NoProfile -Command "try { $res = Invoke-RestMethod -Uri 'http://127.0.0.1:8765/api/health' -TimeoutSec 2; Write-Host 'Cloud-D is RUNNING at http://127.0.0.1:8765/ [Status: OK, Mode: ' $res.mode ']'; $conn = Get-NetTCPConnection -LocalPort 8765 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | Where-Object { $_ -gt 0 }; if ($conn) { Write-Host \"Process ID (PID): $conn\" } } catch { Write-Host 'Cloud-D is NOT running.' }"

set "CODE_FILE=%USERPROFILE%\.cloud-d\staff-registration-code"
if exist "%CODE_FILE%" (
    echo.
    echo Staff Registration Code is saved at: %CODE_FILE%
)
