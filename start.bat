@echo off
setlocal
cd /d "%~dp0"
echo === SimeGuard ===

if not exist ".venv\Scripts\python.exe" (
    echo First run: setting up Python ^(about a minute^)...
    py -3 -m venv .venv 2>nul || python -m venv .venv
    if errorlevel 1 (
        echo Could not create the environment. Install Python 3.12 or 3.13 from python.org and tick "Add to PATH".
        pause
        exit /b 1
    )
)
call ".venv\Scripts\activate.bat"
python -m pip install -q --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo Package install failed. Check your internet connection and try again.
    pause
    exit /b 1
)

cd Simeguard_Backend
if not exist ".env" (
    echo No .env file found, so starting in DEMO mode ^(demo logins + RESET button^).
    echo For real use, copy .env.example to .env and fill it in. See README.md.
    set DEMO_MODE=1
    set SECRET_KEY=demo-only-secret
    set WEBHOOK_API_KEY=dev-webhook-key
)

echo.
echo Dashboard: http://127.0.0.1:8000/dashboard    ^(stop with Ctrl+C^)
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:8000/dashboard"
python -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
