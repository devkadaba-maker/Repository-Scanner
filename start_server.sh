#!/usr/bin/env bash
source "$(dirname "$0")/.venv/bin/activate" && uvicorn server:app --host 0.0.0.0 --port 7860 --reload
