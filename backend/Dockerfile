# One image for the migrate, api, worker and beat services (see docker-compose.yml);
# each service overrides `command`. No HEALTHCHECK here: it would apply to every
# service, and only `api` serves HTTP.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first so code changes don't invalidate this layer.
COPY pyproject.toml ./
RUN mkdir app && touch app/__init__.py \
    && pip install . \
    && pip uninstall -y sentinel-ai \
    && rm -rf app build *.egg-info

COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app

# Non-root user with a fixed UID (needed for runAsNonRoot on K3s later).
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --shell /usr/sbin/nologin --no-create-home appuser \
    && mkdir -p /data/faiss && chown -R appuser:appuser /app /data
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
