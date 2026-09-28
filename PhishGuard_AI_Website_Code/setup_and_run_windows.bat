@echo off
cd /d "%~dp0"
python -m pip install -r requirements.txt
python scripts\download_datasets.py
python scripts\train_and_evaluate.py --max-rows 100000 --trees 200
python app\app.py
pause
