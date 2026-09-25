"""Central configuration. Values can be overridden with environment variables or a .env file."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    return value.strip() if value and value.strip() else default


DATASET_PATH = Path(_env("DATASET_PATH", str(BASE_DIR / "data" / "email_dataset.csv")))
MODEL_PATH = Path(_env("MODEL_PATH", str(BASE_DIR / "models" / "email_nlp_model.joblib")))
DATABASE_PATH = Path(_env("DATABASE_PATH", str(BASE_DIR / "data" / "emailsentinel.db")))
DATABASE_URL = _env("DATABASE_URL", f"sqlite:///{DATABASE_PATH}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]
DATABASE_ECHO = _bool("DATABASE_ECHO", False)

# External lookups (all optional and fail gracefully)
ENABLE_GEOLOCATION = _bool("ENABLE_GEOLOCATION", True)
ENABLE_DNS = _bool("ENABLE_DNS", True)
ENABLE_WHOIS = _bool("ENABLE_WHOIS", False)  # slow and often rate limited, off by default
GEO_API_URL = _env("GEO_API_URL", "http://ip-api.com/json")
HTTP_TIMEOUT = float(_env("HTTP_TIMEOUT", "4"))
DNS_TIMEOUT = float(_env("DNS_TIMEOUT", "2.5"))
THREAT_INTEL_ENABLED = _bool("THREAT_INTEL_ENABLED", False)
ABUSEIPDB_API_KEY = _env("ABUSEIPDB_API_KEY", "")
TOR_EXIT_LIST_URL = _env("TOR_EXIT_LIST_URL", "https://check.torproject.org/torbulkexitlist")
THREAT_INTEL_TIMEOUT = float(_env("THREAT_INTEL_TIMEOUT", "5"))
THREAT_INTEL_DNSBL = _env("THREAT_INTEL_DNSBL", "zen.spamhaus.org")

MAX_EMAIL_BYTES = int(_env("MAX_EMAIL_BYTES", str(5 * 1024 * 1024)))
MASK_SENSITIVE_FIELDS = _bool("MASK_SENSITIVE_FIELDS", False)
RETENTION_ENABLED = _bool("RETENTION_ENABLED", False)
RETENTION_DAYS = int(_env("RETENTION_DAYS", "365"))

# Redis is optional for local/offline analysis. PostgreSQL remains the source of truth.
REDIS_ENABLED = _bool("REDIS_ENABLED", True)
REDIS_URL = _env("REDIS_URL", "redis://localhost:6379/0")
REDIS_TIMEOUT = float(_env("REDIS_TIMEOUT", "1.5"))
REDIS_DNS_TTL = int(_env("REDIS_DNS_TTL", "3600"))
REDIS_IP_TTL = int(_env("REDIS_IP_TTL", "21600"))
REDIS_WHOIS_TTL = int(_env("REDIS_WHOIS_TTL", "86400"))
REDIS_THREAT_INTEL_TTL = int(_env("REDIS_THREAT_INTEL_TTL", "3600"))

CELERY_BROKER_URL = _env("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = _env("CELERY_RESULT_BACKEND", REDIS_URL)
CELERY_SOFT_TIME_LIMIT = int(_env("CELERY_SOFT_TIME_LIMIT", "240"))
CELERY_TIME_LIMIT = int(_env("CELERY_TIME_LIMIT", "300"))
CELERY_RESULT_EXPIRES = int(_env("CELERY_RESULT_EXPIRES", "86400"))
ASYNC_ANALYSIS_ENABLED = _bool("ASYNC_ANALYSIS_ENABLED", False)
