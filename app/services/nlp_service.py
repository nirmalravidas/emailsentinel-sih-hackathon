"""NLP service: TF-IDF + Logistic Regression classifier plus rule-based heuristics.

The two parts are deliberately kept separate:
  * ML result   -> classification, confidence, class_probabilities, keywords
  * Heuristics  -> social_engineering_indicators, heuristic_flags, heuristic_matches

Only plain scikit-learn objects are pickled (text cleaning happens outside the pipeline), so the
saved model loads no matter how the app is started.

Train / retrain from the command line:   python -m app.services.nlp_service
"""
from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline

from app import config

logger = logging.getLogger("emailsentinel.nlp")

# --------------------------------------------------------------------------- text cleaning
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_URL_RE = re.compile(r"https?://\S+", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_NUM_RE = re.compile(r"\b\d+\b")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9\s]")
_WS_RE = re.compile(r"\s+")


def clean_text(text: str) -> str:
    """Lowercase, strip HTML, replace URLs/emails with placeholder tokens, drop punctuation/numbers."""
    t = text or ""
    t = _URL_RE.sub(" urltoken ", t)
    t = _EMAIL_RE.sub(" emailtoken ", t)
    t = _HTML_TAG_RE.sub(" ", t)
    t = t.lower()
    t = _NON_ALNUM_RE.sub(" ", t)
    t = _NUM_RE.sub(" ", t)
    return _WS_RE.sub(" ", t).strip()


# --------------------------------------------------------------------------- training / loading
def build_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(ngram_range=(1, 2), stop_words="english", sublinear_tf=True),
            ),
            ("clf", LogisticRegression(C=10, max_iter=2000, class_weight="balanced")),
        ]
    )


def train_model() -> Dict[str, Any]:
    """Train on data/email_dataset.csv and save the pipeline with joblib."""
    df = pd.read_csv(config.DATASET_PATH).dropna(subset=["text", "label"])
    texts = [clean_text(t) for t in df["text"].astype(str)]
    labels = df["label"].astype(str).tolist()

    pipe = build_pipeline()
    metrics: Dict[str, Any] = {"samples": len(texts), "classes": sorted(set(labels))}

    min_class = min(labels.count(c) for c in set(labels))
    if min_class >= 5:
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        scores = cross_val_score(build_pipeline(), texts, labels, cv=cv, scoring="accuracy")
        metrics["cv_accuracy_mean"] = round(float(scores.mean()), 3)

    pipe.fit(texts, labels)
    config.MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, config.MODEL_PATH)
    metrics["model_path"] = str(config.MODEL_PATH)
    get_model.cache_clear()
    logger.info("Model trained: %s", metrics)
    return metrics


@lru_cache(maxsize=1)
def get_model() -> Pipeline:
    if not config.MODEL_PATH.exists():
        logger.warning("No saved model found, training a new one from %s", config.DATASET_PATH)
        train_model()
    try:
        return joblib.load(config.MODEL_PATH)
    except Exception as exc:  # e.g. model saved with a different scikit-learn version
        logger.warning("Could not load saved model (%s); retraining from %s", exc, config.DATASET_PATH)
        train_model()
        return joblib.load(config.MODEL_PATH)


# --------------------------------------------------------------------------- heuristics
_HEURISTIC_PATTERNS: Dict[str, Dict[str, Any]] = {
    "urgency": {
        "label": "urgency",
        "regex": re.compile(
            r"\b(urgent(?:ly)?|immediate(?:ly)?|right away|asap|act now|last chance|final (?:notice|warning)"
            r"|time[- ]sensitive|without delay|within \d+\s*(?:hours?|hrs?|minutes?|mins?|days?)"
            r"|expires? (?:today|soon|in \d+)|(?:24|48|12) hours)\b",
            re.I,
        ),
    },
    "financial_request": {
        "label": "financial request",
        "regex": re.compile(
            r"\b(wire transfer|bank (?:details|account)|send (?:me )?(?:money|payment|funds)|processing fee"
            r"|release fee|claim fee|gift cards?|bitcoin|crypto(?:currency)?|western union|payment (?:is )?"
            r"(?:due|failed|required|pending|overdue)|update your (?:billing|payment)|billing information"
            r"|card number|credit card|debit card|refund|lottery|inheritance|deposit)\b",
            re.I,
        ),
    },
    "credential_request": {
        "label": "credential request",
        "regex": re.compile(
            r"\b((?:verify|confirm|validate|update|re-?enter|provide|submit|enter|share|send)\s+(?:your\s+)?"
            r"(?:account|password|login|log-in|credentials?|identity|pin|otp|cvv|card|bank|kyc|pan|aadhaar"
            r"|personal|username)\b|sign in with your (?:email )?password|username and password)",
            re.I,
        ),
    },
    "account_suspension": {
        "label": "account suspension threat",
        "regex": re.compile(
            r"(?:\b(?:account|access|card|mailbox|membership|service)\b[^.\n]{0,40}\b(?:suspend\w*|locked|"
            r"blocked|deactivat\w*|disabled|terminat\w*|restricted|closed|frozen)\b"
            r"|\b(?:suspend|lock|block|deactivate|terminate|restrict|freeze|close)\w*\s+(?:your\s+)?"
            r"(?:account|access|mailbox))",
            re.I,
        ),
    },
    "impersonation_language": {
        "label": "impersonation language",
        "regex": re.compile(
            r"\b((?:security|support|customer service|billing|account|it|hr|help ?desk)\s+team"
            r"|(?:microsoft|google|paypal|amazon|apple|sbi|state bank of india|netflix|hdfc|icici)\b[^.\n]{0,30}"
            r"\b(?:team|support|security|department|helpdesk)|official (?:notice|notification|communication))",
            re.I,
        ),
    },
    "suspicious_cta": {
        "label": "suspicious call-to-action",
        "regex": re.compile(
            r"\b(click (?:here|the link|the button|below|on the link)|(?:click|tap|follow|open|use) the (?:link|button)"
            r"|verify now|log ?in now|sign ?in now|confirm now|update now|download the attachment|open the attached)\b",
            re.I,
        ),
    },
}


def extract_heuristics(text: str) -> Dict[str, Any]:
    """Rule-based social-engineering detection (independent from the ML model)."""
    flags: Dict[str, bool] = {}
    matches: Dict[str, List[str]] = {}
    indicators: List[str] = []
    for key, spec in _HEURISTIC_PATTERNS.items():
        found = []
        for m in spec["regex"].finditer(text or ""):
            s = m.group(0).strip()
            if s.lower() not in [f.lower() for f in found]:
                found.append(s)
        flags[key] = bool(found)
        if found:
            matches[key] = found[:4]
            indicators.append(spec["label"])
    return {"indicators": indicators, "flags": flags, "matches": matches}


# --------------------------------------------------------------------------- ML explanation
def _top_keywords(pipe: Pipeline, cleaned: str, class_idx: int, limit: int = 6) -> List[str]:
    """Words in this text that pushed the model most strongly towards the predicted class."""
    vec: TfidfVectorizer = pipe.named_steps["tfidf"]
    clf: LogisticRegression = pipe.named_steps["clf"]
    X = vec.transform([cleaned])
    coef = clf.coef_
    weights = coef[class_idx] if coef.shape[0] > 1 else (coef[0] if class_idx == 1 else -coef[0])
    names = vec.get_feature_names_out()
    cols = X.nonzero()[1]
    scored = [(float(X[0, j] * weights[j]), names[j]) for j in cols if " " not in names[j]]
    scored = [s for s in scored if s[0] > 0]
    scored.sort(reverse=True)
    return [w for _, w in scored[:limit]]


# --------------------------------------------------------------------------- public API
def analyze_text(text: str) -> Dict[str, Any]:
    pipe = get_model()
    cleaned = clean_text(text)
    heur = extract_heuristics(text)

    if not cleaned:
        return {
            "classification": "unknown",
            "confidence": 0.0,
            "class_probabilities": {},
            "keywords": [],
            "social_engineering_indicators": heur["indicators"],
            "heuristic_flags": heur["flags"],
            "heuristic_matches": heur["matches"],
        }

    proba = pipe.predict_proba([cleaned])[0]
    classes = [str(c) for c in pipe.classes_]
    idx = int(np.argmax(proba))
    return {
        # ---- ML result
        "classification": classes[idx],
        "confidence": round(float(proba[idx]), 3),
        "class_probabilities": {c: round(float(p), 3) for c, p in zip(classes, proba)},
        "keywords": _top_keywords(pipe, cleaned, idx),
        # ---- heuristic result (kept separate from the model output)
        "social_engineering_indicators": heur["indicators"],
        "heuristic_flags": heur["flags"],
        "heuristic_matches": heur["matches"],
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(train_model())
