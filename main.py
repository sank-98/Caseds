import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from caseds.config import settings
from caseds.models.schemas import HealthResponse, IntelligenceResult, RawInput
from caseds.pipeline.feature_extraction import extract_bundle
from caseds.pipeline.input_layer import normalizer
from caseds.pipeline.intelligence import classify, match_patterns, score_threat

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("caseds.api")


class RequestLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        kwargs.setdefault("extra", {}).setdefault("request_id", self.extra.get("request_id", "-"))
        return msg, kwargs


app = FastAPI(title=settings.app_name, version=settings.version)


@app.middleware("http")
async def request_tracking(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id

    adapter = RequestLoggerAdapter(logger, {"request_id": request_id})
    start = time.perf_counter()
    try:
        response = await call_next(request)
    finally:
        duration_ms = (time.perf_counter() - start) * 1000
        adapter.info(
            "request_complete request_id=%s method=%s path=%s duration_ms=%.2f",
            request_id,
            request.method,
            request.url.path,
            duration_ms,
        )

    response.headers["X-Request-ID"] = request_id
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", "-")
    adapter = RequestLoggerAdapter(logger, {"request_id": request_id})
    adapter.warning("validation_error request_id=%s details=%s", request_id, exc.errors())
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "request_id": request_id},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", "-")
    adapter = RequestLoggerAdapter(logger, {"request_id": request_id})
    adapter.exception("unhandled_error request_id=%s", request_id)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request_id},
    )


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=settings.version,
        modules_loaded={
            "input_layer": True,
            "feature_extraction": True,
            "intelligence": True,
            "api": True,
        },
    )


@app.post("/analyze")
def analyze(payload: RawInput):
    start = time.perf_counter()

    normalized = normalizer.normalize(payload)
    features = extract_bundle(normalized)
    nlp = classify(normalized, features)
    patterns = match_patterns(normalized, features)
    intelligence = IntelligenceResult(nlp_classification=nlp, pattern_matches=patterns, graph_clusters=[])

    elapsed = (time.perf_counter() - start) * 1000
    return score_threat(normalized, features, intelligence, elapsed)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=settings.api_host, port=settings.api_port, reload=settings.debug)
