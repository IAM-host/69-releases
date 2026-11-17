@echo off
setlocal
cd /d "%~dp0"
call setup_env.bat
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -r requirements-build.txt
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --name L main.py
if errorlevel 1 goto failed
echo.
echo Build complete: "%CD%\dist\L.exe"
pause
exit /b 0
:failed
echo Build failed. Check the error above.
pause
exit /b 1
