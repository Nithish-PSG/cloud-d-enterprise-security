@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -m cloud_d.main
) else (
  python -m cloud_d.main
)
if errorlevel 1 pause
