FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini README.md .env.example ./
COPY data ./data
COPY models ./models
COPY frontend ./frontend

RUN useradd --create-home --uid 10001 emailsentinel && \
    chown -R emailsentinel:emailsentinel /app
USER emailsentinel

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
