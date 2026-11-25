@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Apply-EUNORA-Native.ps1" %*
set "EUNORA_NATIVE_EXIT=%ERRORLEVEL%"
pause
exit /b %EUNORA_NATIVE_EXIT%
