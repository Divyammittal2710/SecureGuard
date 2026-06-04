# backend/app.py
from fastapi import FastAPI
from schemas import CodeRequest
from database import init_db, get_full_scan_history, reset_scan_history
from security_graph import security_graph


app = FastAPI()

init_db()


@app.get("/")
def home():
    return {"message": "SecureGuard Running"}


@app.post("/analyze")
def analyze(request: CodeRequest):
    result = security_graph.invoke({"code": request.code})

    return {
        "findings": result["findings"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "report": result.get("report", ""),
    }


@app.delete("/history/reset")
def clear_history():
    reset_scan_history()
    return {"message": "Scan history cleared"}


@app.get("/history")
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
