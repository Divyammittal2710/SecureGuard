# backend/app.py
import os
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from schemas import CodeRequest
from database import init_db, get_full_scan_history, reset_scan_history
from security_graph import security_graph


def get_api_key_or_ip(request: Request) -> str:
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

API_KEY = os.getenv("API_KEY", "")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")


def verify_admin_key(x_api_key: str = Header(default="")):
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=500, detail="ADMIN_API_KEY not configured on server")
    if not x_api_key or x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")


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
    if not API_KEY:
        raise HTTPException(status_code=500, detail="API_KEY not configured on server")
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    result = security_graph.invoke({
        "code": code_request.code,
        "language": code_request.language.value  # pass language to graph
    })
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


@app.get("/history")
@limiter.limit("30/minute")
async def history(
    request: Request,
    x_api_key: str = Header(default="")
):
    if not API_KEY:
        raise HTTPException(status_code=500, detail="API_KEY not configured on server")
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    rows = get_full_scan_history()
    return [
        {
            "id": row[0],
            "risk_score": row[1],
            "risk_level": row[2],
            "created_at": row[3],
        }
        for row in rows
    ]# updated
