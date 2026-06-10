# backend/graph_state_v2.py
from typing import TypedDict, List, Optional


class Finding(TypedDict):
    rule_id: str
    category: str
    line_hint: str
    description: str
    confidence: str    # high / medium / low
    severity: str      # High / Medium / Low
    remediation: str


class PreprocessResult(TypedDict):
    cleaned_code: str
    original_code: str
    imports: List[str]
    has_suspicious_comments: bool
    flagged_comments: List[str]
    language: str


class ScanStateV2(TypedDict):
    # ── Input ────────────────────────────────────────
    code: str
    language: str

    # ── After preprocess ─────────────────────────────
    preprocess_result: Optional[PreprocessResult]

    # ── Findings from each specialist node ───────────
    injection_findings: List[Finding]
    auth_findings: List[Finding]
    secrets_findings: List[Finding]
    dependency_findings: List[Finding]

    # ── After synthesis ──────────────────────────────
    all_findings: List[Finding]
    risk_score: int
    risk_level: str

    # ── Final output ─────────────────────────────────
    report: str
    needs_human_review: List[Finding]  # low confidence findings