#!/bin/sh
set -e
python3 rewrite_flags.py
exec uvicorn main:app --host 0.0.0.0 --port 8001
