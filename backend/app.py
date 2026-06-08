# backend/app.py
import os
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from schemas import CodeRequest
from database import init_db, get_full_scan_history, reset_scan_history, validate_api_key
from security_graph import security_graph


app = FastAPI()

# ---------------------------------------------------------------------------
# CORS — explicitly restrict to the deployed frontend origin only.
# Never use allow_origins=["*"] in production.
# ---------------------------------------------------------------------------
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
# Admin API key — for destructive routes only (DELETE /history/reset).
# ---------------------------------------------------------------------------
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")


# ---------------------------------------------------------------------------
# Auth dependency — validates developer API key on every protected route.
#
# How it works:
#   1. Client sends header:  X-API-Key: <raw_key>
#   2. We hash the raw key with SHA-256
#   3. Compare hash against api_keys table in DB
#   4. If no match → 401 Unauthorized
#
# We return the same error message for missing AND invalid keys
# to avoid leaking whether a key exists (timing/enumeration attack).
# ---------------------------------------------------------------------------
def require_api_key(x_api_key: str = Header(default="")):
    if not x_api_key or not validate_api_key(x_api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )


def verify_admin_key(x_api_key: str = Header(default="")):
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=500, detail="ADMIN_API_KEY not configured on server")
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")


init_db()


@app.get("/")
def home():
    return {"message": "SecureGuard Running"}


@app.post("/analyze", dependencies=[Depends(require_api_key)])
def analyze(request: CodeRequest):
    result = security_graph.invoke({"code": request.code})

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
def history():
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