"""Celery application configuration for EmailSentinel workers."""
from celery import Celery

from app import config

celery_app = Celery(
    "emailsentinel",
    broker=config.CELERY_BROKER_URL,
    backend=config.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    task_soft_time_limit=config.CELERY_SOFT_TIME_LIMIT,
    task_time_limit=config.CELERY_TIME_LIMIT,
    result_expires=config.CELERY_RESULT_EXPIRES,
)
