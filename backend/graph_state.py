# backend/graph_state.py
from typing import TypedDict, List


class ScanState(TypedDict):
    code: str
    language: str          # language passed through the full pipeline
    findings: List[dict]
    risk_score: int
    risk_level: str
    report: str