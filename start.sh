#!/bin/sh
set -eu

echo "[start] Waiting for database..."
until pg_isready -h "${DB_HOST:-db}" -p "${DB_PORT:-5432}" -U "${POSTGRES_USER:-cai}" -d "${POSTGRES_DB:-cai}" >/dev/null 2>&1; do
  sleep 1
done
echo "[start] Database is ready."

echo "[start] Running manage.py init-db (idempotent)"
python manage.py init-db || true

echo "[start] Applying cascade constraints"
python manage.py apply-cascade || true

echo "[start] Launching gunicorn"
exec gunicorn 'run:app' --workers 4 --threads 2 --bind 0.0.0.0:5000 --timeout 60 --forwarded-allow-ips="${FORWARDED_ALLOW_IPS:-*}"
