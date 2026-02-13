FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache curl \
    && pip install --no-cache-dir websocket-client requests flask

COPY ct_monitor.py .
COPY domains.txt .

EXPOSE 8080

CMD ["python3", "ct_monitor.py"]
