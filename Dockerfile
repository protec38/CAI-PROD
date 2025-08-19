FROM python:3.12-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends         build-essential libpq-dev curl postgresql-client       && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# App
COPY . /app/

# Ensure start.sh is executable
RUN chmod +x /app/start.sh

EXPOSE 5000
ENV PYTHONUNBUFFERED=1

CMD ["/app/start.sh"]
