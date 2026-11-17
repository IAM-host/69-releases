@echo off
setlocal
cd /d "%~dp0"
call setup_env.bat
if errorlevel 1 goto failed
".venv\Scripts\python.exe" main.py
if errorlevel 1 goto failed
exit /b 0
:failed
pause
exit /b 1
