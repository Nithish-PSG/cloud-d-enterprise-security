@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "DATA_DIR=%USERPROFILE%\.cloud-d"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

set "CODE_FILE=%DATA_DIR%\staff-registration-code"
if not exist "%CODE_FILE%" (
    powershell -NoProfile -Command "$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; $rnd = -join ((1..32) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] }); 'CLOUD-D-' + $rnd | Set-Content -Path '%CODE_FILE%' -Encoding utf8"
)

if exist "%CODE_FILE%" (
    set /p CLOUD_D_STAFF_REGISTRATION_CODE=<"%CODE_FILE%"
    export CLOUD_D_STAFF_REGISTRATION_CODE 2>nul
)

where py >nul 2>nul
if %errorlevel% equ 0 (
  set "PYTHON_CMD=py -3"
) else (
  where python >nul 2>nul
  if errorlevel 1 (
    echo Cloud-D needs Python 3.10 or newer. Install Python from https://www.python.org/downloads/ and try again.
    pause
    exit /b 1
  )
  set "PYTHON_CMD=python"
)

if not exist ".venv\Scripts\python.exe" (
  echo Preparing Cloud-D Python environment...
  %PYTHON_CMD% -m venv .venv
  if errorlevel 1 goto setup_failed
)

if not exist ".venv\.cloud_d_dependencies_ready" (
  echo Installing Cloud-D encryption support...
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 goto setup_failed
  type nul > ".venv\.cloud_d_dependencies_ready"
)

:: Check if server is already running on port 8765
powershell -NoProfile -Command "try { $res = Invoke-RestMethod -Uri 'http://127.0.0.1:8765/api/health' -TimeoutSec 2; if ($res.ok) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 (
    echo Cloud-D is already running. Opening dashboard in browser...
    start "" "http://127.0.0.1:8765/"
    exit /b 0
)

echo Starting Cloud-D background service...
powershell -NoProfile -Command "Start-Process -FilePath '.\.venv\Scripts\pythonw.exe' -ArgumentList '-m', 'cloud_d.main', '--no-browser', '--host', '127.0.0.1', '--port', '8765' -RedirectStandardOutput '%DATA_DIR%\server.log' -RedirectStandardError '%DATA_DIR%\server_error.log' -WindowStyle Hidden"

:: Wait up to 10 seconds for health check to confirm startup
powershell -NoProfile -Command "$deadline = (Get-Date).AddSeconds(10); while ((Get-Date) -lt $deadline) { try { $r = Invoke-RestMethod -Uri 'http://127.0.0.1:8765/api/health' -TimeoutSec 1; if ($r.ok) { exit 0 } } catch {}; Start-Sleep -Milliseconds 400 }; exit 1"
if %errorlevel% equ 0 (
    echo Cloud-D background service started successfully.
    start "" "http://127.0.0.1:8765/"
    exit /b 0
) else (
    echo Cloud-D background service failed to start. Check log at: %DATA_DIR%\server.log and %DATA_DIR%\server_error.log
    exit /b 1
)

:setup_failed
echo Cloud-D could not prepare its Python environment. Check your connection and try again.
pause
exit /b 1
