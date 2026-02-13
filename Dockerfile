FROM python:3.11-alpine

WORKDIR /app

# Installation des dépendances système et Python
RUN apk add --no-cache curl gcc musl-dev libffi-dev openssl-dev \
    && pip install --no-cache-dir requests

# Copie des fichiers
COPY ct_all_logs.py .
COPY domains.txt .

# Exposition du port (par défaut 10000 pour Render)
EXPOSE 10000

# Healthcheck utilisant le serveur HTTP interne
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-10000}/health || exit 1

CMD ["python3", "-u", "ct_all_logs.py"]
