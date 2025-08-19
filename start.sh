#!/usr/bin/env bash
set -euo pipefail

echo "[start] Using FLASK_CONFIG=${FLASK_CONFIG:-prod}"
echo "[start] Waiting for database at db:5432 ..."
# wait for db with pg_isready
for i in $(seq 1 60); do
  if pg_isready -h db -p 5432 -U "${POSTGRES_USER:-cai}" >/dev/null 2>&1; then
    echo "[start] Database is ready."
    break
  fi
  echo "[start] ... not ready yet (${i}/60)"; sleep 1
done

# Run one-time DB init (idempotent)
if [ ! -f /app/.db_init_done ]; then
  echo "[start] Running manage.py init-db (idempotent)"
  python manage.py init-db || echo "[start] init-db returned non-zero; continuing"
  touch /app/.db_init_done
fi

echo "[start] Launching gunicorn"
exec gunicorn 'run:app' --workers 4 --threads 2 --bind 0.0.0.0:5000 --timeout 60
