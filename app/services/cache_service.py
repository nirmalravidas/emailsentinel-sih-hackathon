"""Best-effort Redis cache-aside service.

Redis is an optimization and temporary-state store; lookup failures never fail analysis.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

import redis

from app import config

logger = logging.getLogger("emailsentinel.cache")
_client: Optional[redis.Redis] = None


def client() -> Optional[redis.Redis]:
    global _client
    if not config.REDIS_ENABLED:
        return None
    if _client is None:
        try:
            _client = redis.Redis.from_url(
                config.REDIS_URL,
                socket_connect_timeout=config.REDIS_TIMEOUT,
                socket_timeout=config.REDIS_TIMEOUT,
                decode_responses=True,
            )
        except Exception as exc:
            logger.warning("Redis client initialization failed: %s", exc)
            return None
    return _client


def get_json(key: str) -> Optional[Any]:
    cache = client()
    if cache is None:
        return None
    try:
        value = cache.get(key)
        return json.loads(value) if value else None
    except (redis.RedisError, ValueError) as exc:
        logger.warning("Redis read failed for %s: %s", key, exc)
        return None


def set_json(key: str, value: Any, ttl: int) -> bool:
    cache = client()
    if cache is None:
        return False
    try:
        cache.setex(key, ttl, json.dumps(value, default=str))
        return True
    except (redis.RedisError, TypeError, ValueError) as exc:
        logger.warning("Redis write failed for %s: %s", key, exc)
        return False


def ping() -> bool:
    cache = client()
    if cache is None:
        return False
    try:
        return bool(cache.ping())
    except redis.RedisError:
        return False
