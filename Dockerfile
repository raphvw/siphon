FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py index.html siphon.png ./
ENV CONFIG_PATH=/config/config.yaml ALLOWED_DEST_ROOTS=/data
EXPOSE 8080
CMD ["uvicorn", "app:api", "--host", "0.0.0.0", "--port", "8080"]
