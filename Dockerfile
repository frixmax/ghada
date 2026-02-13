FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache curl \
    && pip install --no-cache-dir websocket-client requests

COPY ct_monitor.py .
COPY domains.txt .

CMD ["python3", "ct_monitor.py"]
