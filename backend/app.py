# backend/app.py
import os
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from schemas import CodeRequest, detect_language
from database import init_db, get_full_scan_history, reset_scan_history
from security_graph import security_graph


# ---------------------------------------------------------------------------
# Rate limiter — keyed by API key, falls back to IP if no key present.
# Per-key limiting means each developer has their own independent quota.
# This is how OpenAI, Stripe, and Snyk implement rate limiting.
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

app = FastAPI()

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

# ---------------------------------------------------------------------------
# API key auth — validated against API_KEY environment variable.
# Keys are stored as Azure Container Apps secrets — never in code.
# Same error message for missing AND invalid keys — prevents
# attackers from knowing whether a key exists.
# ---------------------------------------------------------------------------
API_KEY = os.getenv("API_KEY", "")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")


def verify_admin_key(x_api_key: str = Header(default="")):
    """
    Admin key validated against ADMIN_API_KEY env var.
    Used only for destructive operations like history reset.
    Regular API key holders cannot perform admin operations.
    """
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
@limiter.limit("10/minute")
async def analyze(
    request: Request,
    code_request: CodeRequest,
    x_api_key: str = Header(default="")
):
    """
    10 requests per minute per API key.
    Prevents token exhaustion attacks on Azure AI Foundry.
    A legitimate developer rarely needs more than 10 scans/minute.
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
        "findings": result["findings"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "report": result.get("report", ""),
    }


@app.post("/detect-language")
@limiter.limit("60/minute")
async def detect_language_endpoint(
    request: Request,
    code_request: CodeRequest,
    x_api_key: str = Header(default="")
):
    """
    Detects the language of submitted code using heuristics.
    Returns detected language and whether it matches submitted language.
    60 requests per minute — lightweight endpoint, no AI call.
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
@limiter.limit("30/minute")
async def history(
    request: Request,
    x_api_key: str = Header(default="")
):
    """
    30 requests per minute — history is cheaper than analyze
    (no AI call) so a higher limit is fine.
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