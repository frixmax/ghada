FROM python:3.11-alpine

WORKDIR /app

# Install minimal deps
RUN apk add --no-cache curl \
    && pip install --no-cache-dir websocket-client requests

# Copy files
COPY ct_monitor.py .
COPY domains.txt .

# Run the monitoring script
CMD ["python3", "ct_monitor.py"]
