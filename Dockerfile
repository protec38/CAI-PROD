FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      libpq5 postgresql-client curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1) Dépendances (cache-friendly)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# 2) Code de l'app (copie explicite = plus fiable)
COPY app /app/app
COPY manage.py run.py start.sh /app/

# 3) SQL de cascade (IMPORTANT pour éviter "Fichier SQL introuvable")
#    -> assure-toi que ce fichier existe dans ton repo: db/alter_cascade.sql
COPY db/ /app/db/

# 4) Normalisation + exécutable
RUN sed -i 's/\r$//' /app/start.sh && chmod +x /app/start.sh

EXPOSE 5000
CMD ["/bin/sh","/app/start.sh"]
