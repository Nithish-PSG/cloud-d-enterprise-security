@echo off
setlocal
cd /d "%~dp0"

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
  echo Creating the Cloud-D Python environment...
  %PYTHON_CMD% -m venv .venv
  if errorlevel 1 goto setup_failed
)

if not exist ".venv\.cloud_d_dependencies_ready" (
  echo Installing Cloud-D encryption support...
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 goto setup_failed
  type nul > ".venv\.cloud_d_dependencies_ready"
)

".venv\Scripts\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
  echo Cloud-D needs Python 3.10 or newer. The installed Python is too old.
  pause
  exit /b 1
)

echo Starting Cloud-D. Keep this window open while using the dashboard.
".venv\Scripts\python.exe" -m cloud_d.main
if errorlevel 1 pause
exit /b

:setup_failed
echo Cloud-D could not prepare its Python environment. Check your internet connection and try again.
pause
exit /b 1
