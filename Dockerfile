FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel_ops/ ./sentinel_ops/
COPY evaluations/ ./evaluations/
COPY pyproject.toml README.md ./

RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

CMD ["adk", "api_server", "--host=0.0.0.0", "--port=8080", "sentinel_ops"]
