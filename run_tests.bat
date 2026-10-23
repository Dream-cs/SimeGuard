@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\activate.bat" (
    echo Run start.bat once first so the environment exists.
    pause
    exit /b 1
)
call ".venv\Scripts\activate.bat"
python -m pip install -q --disable-pip-version-check -r requirements-dev.txt
cd Simeguard_Backend
python -m pytest -q
pause
