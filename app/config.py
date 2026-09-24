"""Central configuration. Values can be overridden with environment variables or a .env file."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


DATASET_PATH = Path(os.getenv("DATASET_PATH", BASE_DIR / "data" / "email_dataset.csv"))
MODEL_PATH = Path(os.getenv("MODEL_PATH", BASE_DIR / "models" / "email_nlp_model.joblib"))
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", BASE_DIR / "data" / "emailsentinel.db"))

# External lookups (all optional and fail gracefully)
ENABLE_GEOLOCATION = _bool("ENABLE_GEOLOCATION", True)
ENABLE_DNS = _bool("ENABLE_DNS", True)
ENABLE_WHOIS = _bool("ENABLE_WHOIS", False)  # slow and often rate limited, off by default
GEO_API_URL = os.getenv("GEO_API_URL", "http://ip-api.com/json")
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "4"))
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "2.5"))

MAX_EMAIL_BYTES = int(os.getenv("MAX_EMAIL_BYTES", str(5 * 1024 * 1024)))
