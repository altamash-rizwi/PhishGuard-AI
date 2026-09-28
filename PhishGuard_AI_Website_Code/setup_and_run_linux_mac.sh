#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 -m pip install -r requirements.txt
python3 scripts/download_datasets.py
python3 scripts/train_and_evaluate.py --max-rows 100000 --trees 200
python3 app/app.py
