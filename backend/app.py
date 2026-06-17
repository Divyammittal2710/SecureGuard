# backend/app.py
import os
import logging
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from schemas import CodeRequest, detect_language
from database import init_db, get_full_scan_history, reset_scan_history
from security_graph_v2 import security_graph_v2 as security_graph

# ---------------------------------------------------------------------------
# Logging — structured logs, never log sensitive values like API keys
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rate limit config — controlled via env vars.
# Production: 20/hour on analyze to control Azure OpenAI costs.
# Development: override with higher limits in .env for easy testing.
# ---------------------------------------------------------------------------
ANALYZE_RATE_LIMIT = os.getenv("ANALYZE_RATE_LIMIT", "20/hour")
HISTORY_RATE_LIMIT = os.getenv("HISTORY_RATE_LIMIT", "60/hour")
DETECT_RATE_LIMIT = os.getenv("DETECT_RATE_LIMIT", "100/hour")

# ---------------------------------------------------------------------------
# Rate limiter — keyed by API key, falls back to IP if no key present.
# ---------------------------------------------------------------------------
def get_api_key_or_ip(request: Request) -> str:
    """
    Use the API key as the rate limit identifier if present.
    Falls back to IP address for unauthenticated requests.
    """
    api_key = request.headers.get("x-api-key", "")
    if api_key:
        return api_key
    return get_remote_address(request)


limiter = Limiter(key_func=get_api_key_or_ip)

# ---------------------------------------------------------------------------
# App — /docs and /redoc disabled in production.
# Set DEBUG=true locally to enable Swagger UI.
# ---------------------------------------------------------------------------
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

app = FastAPI(
    title="SecureGuard API",
    docs_url="/docs" if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
    openapi_url="/openapi.json" if DEBUG else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ALLOWED_ORIGIN = os.getenv(
    "ALLOWED_ORIGIN",
    "https://secureguard-frontend.jollyhill-a64c45f6.eastus.azurecontainerapps.io"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY", "")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

# ---------------------------------------------------------------------------
# Global exception handlers — structured JSON, no stack traces, no internals
# ---------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Override FastAPI's default 422 handler.
    Default exposes internal field names and types — we sanitize it.
    """
    errors = []
    for error in exc.errors():
        field = " → ".join(str(loc) for loc in error["loc"] if loc != "body")
        errors.append({
            "field": field,
            "message": error["msg"]
        })
    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_error",
            "message": "Invalid request data",
            "details": errors
        }
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Override FastAPI's default HTTP exception handler.
    Returns consistent JSON structure for all HTTP errors.
    """
    error_codes = {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        429: "rate_limit_exceeded",
        500: "internal_error",
    }
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": error_codes.get(exc.status_code, "http_error"),
            "message": exc.detail
        }
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all for unhandled exceptions.
    Logs the real error internally but never exposes it to the client.
    No stack traces, no file paths, no Azure URLs in the response.
    """
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_error",
            "message": "An unexpected error occurred. Please try again later."
        }
    )


def verify_admin_key(x_api_key: str = Header(default="")):
    if not ADMIN_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="ADMIN_API_KEY not configured on server"
        )
    if not x_api_key or x_api_key != ADMIN_API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing API key"
        )


init_db()


@app.get("/")
def home():
    return {"message": "SecureGuard Running"}


@app.post("/analyze")
@limiter.limit(ANALYZE_RATE_LIMIT)
async def analyze(
    request: Request,
    code_request: CodeRequest,
    x_api_key: str = Header(default="")
):
    """
    Rate limit controlled via ANALYZE_RATE_LIMIT env var.
    Default: 20/hour in production to control Azure OpenAI costs.
    """
    if not API_KEY:
        raise HTTPException(
            status_code=500,
            detail="API_KEY not configured on server"
        )
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )

    result = security_graph.invoke({
        "code": code_request.code,
        "language": code_request.language.value
    })
    return {
    "findings": result.get("all_findings", []),
    "risk_score": result.get("risk_score", 0),
    "risk_level": result.get("risk_level", "Low"),
    "report": result.get("report", ""),
    }


@app.post("/detect-language")
@limiter.limit(DETECT_RATE_LIMIT)
async def detect_language_endpoint(
    request: Request,
    code_request: CodeRequest,
    x_api_key: str = Header(default="")
):
    """
    Detects the language of submitted code using heuristics.
    Rate limit controlled via DETECT_RATE_LIMIT env var.
    Default: 100/hour — lightweight, no AI call.
    """
    if not API_KEY:
        raise HTTPException(
            status_code=500,
            detail="API_KEY not configured on server"
        )
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )

    detected = detect_language(code_request.code)
    submitted = code_request.language.value
    match = detected == submitted or detected == "unknown"

    return {
        "detected": detected,
        "submitted": submitted,
        "match": match
    }


@app.delete("/history/reset")
def clear_history(x_api_key: str = Header(default="")):
    verify_admin_key(x_api_key)
    reset_scan_history()
    return {"message": "Scan history cleared"}


@app.get("/history")
@limiter.limit(HISTORY_RATE_LIMIT)
async def history(
    request: Request,
    x_api_key: str = Header(default="")
):
    """
    Rate limit controlled via HISTORY_RATE_LIMIT env var.
    Default: 60/hour — no AI call so higher limit is fine.
    """
    if not API_KEY:
        raise HTTPException(
            status_code=500,
            detail="API_KEY not configured on server"
        )
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )

    rows = get_full_scan_history()
    return [
        {
            "id": row[0],
            "risk_score": row[1],
            "risk_level": row[2],
            "created_at": row[3],
        }
        for row in rows
    ]