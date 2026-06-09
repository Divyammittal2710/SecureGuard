# backend/app.py
import os
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from schemas import CodeRequest
from database import init_db, get_full_scan_history, reset_scan_history, validate_api_key
from security_graph import security_graph


# ---------------------------------------------------------------------------
# Rate limiter — keyed by API key, falls back to IP if no key present.
# Per-key limiting means each developer has their own quota.
# This is how OpenAI, Stripe, and Snyk implement rate limiting.
# ---------------------------------------------------------------------------
def get_api_key_or_ip(request: Request) -> str:
    """
    Use the API key as the rate limit identifier if present.
    Falls back to IP address for unauthenticated requests.
    This ensures each developer key has its own independent quota.
    """
    api_key = request.headers.get("x-api-key", "")
    if api_key:
        return api_key
    return get_remote_address(request)


limiter = Limiter(key_func=get_api_key_or_ip)

app = FastAPI()

# Register rate limit exceeded handler — returns 429 with clear message
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
# API key auth — keys are stored hashed in SQLite via database.py.
# validate_api_key hashes the incoming key and compares against stored hash.
# Never stores or compares plaintext keys.
# ---------------------------------------------------------------------------
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")


def require_api_key(x_api_key: str = Header(default="")):
    """
    Validates developer API key on every protected route.
    Hashes the incoming key and checks against the database.
    Same error message for missing AND invalid keys — prevents
    attackers from knowing whether a key exists.
    """
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    if not validate_api_key(x_api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def verify_admin_key(x_api_key: str = Header(default="")):
    """
    Admin key validated against ADMIN_API_KEY env var.
    Used only for destructive operations like history reset.
    """
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=500, detail="ADMIN_API_KEY not configured on server")
    if not x_api_key or x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")


init_db()


@app.get("/")
def home():
    return {"message": "SecureGuard Running"}


@app.post("/analyze", dependencies=[Depends(require_api_key)])
@limiter.limit("10/minute")
def analyze(request: Request, code_request: CodeRequest):
    """
    10 requests per minute per API key.
    Prevents token exhaustion attacks on Azure AI Foundry.
    A legitimate developer rarely needs more than 10 scans/minute.
    """
    result = security_graph.invoke({"code": code_request.code})
    return {
        "findings": result["findings"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "report": result.get("report", ""),
    }


@app.delete("/history/reset")
def clear_history(x_api_key: str = Header(default="")):
    verify_admin_key(x_api_key)
    reset_scan_history()
    return {"message": "Scan history cleared"}


@app.get("/history", dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
def history(request: Request):
    """
    30 requests per minute — history is cheaper than analyze
    (no AI call) so a higher limit is fine.
    """
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