@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\activate.bat" (
    echo Run start.bat once first so the environment exists.
    pause
    exit /b 1
)
call ".venv\Scripts\activate.bat"
cd Simeguard_Backend
if "%WEBHOOK_API_KEY%"=="" if not exist ".env" set WEBHOOK_API_KEY=dev-webhook-key
python ai_simulator.py
pause
