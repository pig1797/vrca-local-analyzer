@echo off
setlocal
cd /d "%~dp0"
if exist "runtime\python.exe" (
  "runtime\python.exe" local_web.py
  goto done
)
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" local_web.py
  goto done
)
where py >nul 2>nul
if not errorlevel 1 (
  py -3 local_web.py
  goto done
)
echo Python runtime not found. Follow README.md or use the portable package.
pause
exit /b 1
:done
if errorlevel 1 pause
