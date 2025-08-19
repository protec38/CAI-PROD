FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# client postgres + curl pour healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpq5 postgresql-client curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 1) convertir CRLF -> LF  2) rendre exécutable
RUN sed -i 's/\r$//' /app/start.sh && chmod +x /app/start.sh

EXPOSE 5000
# Important: on passe explicitement par /bin/sh (évite les soucis de bit +x sur certains FS)
CMD ["/bin/sh","/app/start.sh"]
