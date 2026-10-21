@echo off
setlocal
cd /d "%~dp0"

echo Stopping Cloud-D background service...
powershell -NoProfile -Command "$port = 8765; $proc = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | Where-Object { $_ -gt 0 }; if ($proc) { foreach ($pidNum in $proc) { Stop-Process -Id $pidNum -Force -ErrorAction SilentlyContinue; Write-Host \"Stopped Cloud-D process (PID: $pidNum)\" } } else { Write-Host \"No running Cloud-D service found listening on port $port.\" }"
