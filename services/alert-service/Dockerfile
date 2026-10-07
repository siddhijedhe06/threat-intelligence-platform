FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn mysql-connector-python

COPY . .

EXPOSE 8002

CMD ["python", "-m", "uvicorn", "alert_api:app", "--host", "0.0.0.0", "--port", "8002"]