FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      libpq5 postgresql-client curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY db /app/db 
COPY . .

# Normalize line endings & ensure start.sh is executable
RUN sed -i 's/\r$//' /app/start.sh && chmod +x /app/start.sh

EXPOSE 5000
CMD ["/bin/sh","/app/start.sh"]
