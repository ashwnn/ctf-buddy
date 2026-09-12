#!/bin/sh
# Small entrypoint: seed the database once, then hand the process to gunicorn.
# The fixture has no interest in being a robust production image.
set -eu

python seed.py

exec python -m gunicorn \
  --bind 0.0.0.0:8000 \
  --workers 1 \
  --threads 4 \
  --timeout 30 \
  --access-logfile - \
  --error-logfile - \
  app:app
