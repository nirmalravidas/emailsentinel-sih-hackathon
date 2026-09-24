"""EmailSentinel - prototype FastAPI backend.   Run:  uvicorn app.main:app --reload"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from app.api.routes import router
from app.database import database
from app.models.schemas import HealthResponse
from app.services import nlp_service

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    nlp_service.get_model()  # loads the saved model, or trains one if it is missing
    yield


app = FastAPI(
    title="EmailSentinel",
    version="0.1.0",
    description=(
        "AI-powered email threat detection, geolocation and forensic intelligence - "
        "**prototype for demonstration and research**. IP geolocation shows infrastructure location, "
        "not the attacker's physical location or identity. Risk scores are heuristic, not validated probabilities."
    ),
    lifespan=lifespan,
)
app.include_router(router, prefix="/api/v1")


@app.get("/health", response_model=HealthResponse, tags=["System"])
def health():
    return {"status": "ok", "service": "EmailSentinel"}


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")
