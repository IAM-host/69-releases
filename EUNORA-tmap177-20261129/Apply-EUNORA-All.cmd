@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Apply-EUNORA-All.ps1" %*
set "EUNORA_ALL_EXIT=%ERRORLEVEL%"
pause
exit /b %EUNORA_ALL_EXIT%
