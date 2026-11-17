@echo off
setlocal
cd /d "%~dp0"
call setup_env.bat
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -r requirements-dev.txt
if errorlevel 1 goto failed
set QT_QPA_PLATFORM=offscreen
".venv\Scripts\python.exe" -m pytest -q
if errorlevel 1 goto failed
pause
exit /b 0
:failed
pause
exit /b 1
