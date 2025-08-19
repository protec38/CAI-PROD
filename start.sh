#!/usr/bin/env bash
set -e

echo "[start] Waiting for database..."
until pg_isready -h "${DB_HOST:-db}" -p "${DB_PORT:-5432}" -U "${POSTGRES_USER}" >/dev/null 2>&1; do
  sleep 1
done
echo "[start] Database is ready."

echo "[start] Running manage.py init-db (idempotent)"
if ! python manage.py init-db; then
  echo "[start] init-db returned non-zero; continuing"
fi

echo "[start] Launching gunicorn"
exec gunicorn 'run:app' --workers 4 --threads 2 --bind 0.0.0.0:5000 --timeout 60 --forwarded-allow-ips='*'
