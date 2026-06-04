from typing import TypedDict, List


class ScanState(TypedDict):
    code: str
    findings: List[dict]
    risk_score: int
    risk_level: str
    report: str
