@echo off
rem ThreatLens - one-click start on Windows.
rem Finds Python, installs the backend packages into backend\_deps (first run only),
rem starts the server on http://127.0.0.1:8000 and opens the browser.
setlocal
cd /d "%~dp0"

set "PY="
for %%C in ("py -3.13" "py -3.12" "py -3.11" "py -3" "python") do (
  if not defined PY (
    %%~C -c "import sys; assert sys.version_info >= (3, 11)" >nul 2>&1 && set "PY=%%~C"
  )
)
if not defined PY (
  echo Python 3.11 or newer was not found. Install it from https://www.python.org/downloads/
  echo and tick "Add python.exe to PATH" during setup, then run this file again.
  pause
  exit /b 1
)
echo Using Python: %PY%

set "DEPS=%~dp0backend\_deps"
if not exist "%DEPS%\fastapi\__init__.py" (
  echo Installing backend packages into backend\_deps ^(first run only, needs internet^)...
  %PY% -m pip --version >nul 2>&1 || %PY% -m ensurepip --upgrade
  %PY% -m pip install --disable-pip-version-check --no-warn-script-location --target "%DEPS%" -r backend\requirements.txt
  if errorlevel 1 (
    echo Package installation failed - see the messages above.
    pause
    exit /b 1
  )
)
set "PYTHONPATH=%DEPS%"
set "PYTHONUTF8=1"

if not exist "frontend\dist\index.html" (
  echo The built dashboard is missing. Run:  cd frontend ^&^& npm install ^&^& npm run build
  pause
  exit /b 1
)

echo.
echo Starting ThreatLens on http://127.0.0.1:8000  ^(close this window or press Ctrl+C to stop^)
echo On the Overview page click "Import hybrid dataset (UWF + AIT)" - it takes a few minutes.
start "" cmd /c "timeout /t 6 >nul & start http://127.0.0.1:8000"
cd backend
%PY% -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause
