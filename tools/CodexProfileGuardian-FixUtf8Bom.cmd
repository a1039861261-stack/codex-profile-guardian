@echo off
setlocal
set "SCRIPT=%~dp0CodexProfileGuardian-FixUtf8Bom.ps1"
if not exist "%SCRIPT%" (
  echo Missing script: "%SCRIPT%"
  pause
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
echo.
pause
