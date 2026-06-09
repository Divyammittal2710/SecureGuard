# backend/graph_nodes.py
from graph_state import ScanState
from rule_engine import scan_code
from azure_ai_service import analyze_with_azure
from database import save_scan


NO_FINDINGS_REPORT = """
# No Critical Findings

No obvious OWASP vulnerabilities were detected by the rule engine.

## Note

This does not guarantee that the code is completely secure.
Manual review may still uncover vulnerabilities that pattern matching cannot detect.
"""


def node_scan(state: ScanState) -> dict:
    result = scan_code(state["code"])
    report = "" if result["findings"] else NO_FINDINGS_REPORT
    return {
        "findings": result["findings"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "report": report,
    }


def node_analyze(state: ScanState) -> dict:
    # Pass language to AI so it tailors analysis per language
    report = analyze_with_azure(
        state["code"],
        state["findings"],
        state.get("language", "python")
    )
    return {"report": report}


def node_save(state: ScanState) -> dict:
    save_scan(
        code=state["code"],
        findings=str(state["findings"]),
        risk_score=state["risk_score"],
        risk_level=state["risk_level"],
        report=state.get("report", ""),
    )
    return {}