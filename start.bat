@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment. Is Python 3.12+ installed?
        pause
        exit /b 1
    )
)

echo Installing dependencies...
.venv\Scripts\pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo ERROR: pip install failed.
    pause
    exit /b 1
)

echo Freeing port 8000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000 2^>nul') do (
    taskkill /PID %%a /F >nul 2>&1
)

echo Starting GKE Log Analyzer...
start "" /b .venv\Scripts\python backend\main.py

timeout /t 3 /nobreak >nul
start "" http://localhost:8000

echo Server running at http://localhost:8000 — close this window to stop.
