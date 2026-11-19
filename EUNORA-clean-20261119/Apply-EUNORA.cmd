@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Apply-EUNORA.ps1" %*
set "update_result=%ERRORLEVEL%"
echo.
pause
exit /b %update_result%
