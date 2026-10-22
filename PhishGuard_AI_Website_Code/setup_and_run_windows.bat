@echo off
cd /d "%~dp0"
python -m pip install -r requirements.txt
python app\app.py
pause
