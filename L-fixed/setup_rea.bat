@echo off
setlocal
cd /d "%~dp0"
call setup_env.bat
if errorlevel 1 goto failed
".venv\Scripts\python.exe" install_rea.py %*
if errorlevel 1 goto failed
echo.
echo REA setup complete. Start L and open REA settings.
pause
exit /b 0
:failed
echo REA setup failed. Check the error above. Node.js and a full JDK are required.
pause
exit /b 1
