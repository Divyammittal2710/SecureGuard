# backend/security_graph_v2.py
from langgraph.graph import StateGraph, END
from graph_state_v2 import ScanStateV2
from preprocessor import preprocess
from analyzer_nodes import (
    node_injection_analyzer,
    node_auth_analyzer,
    node_secrets_analyzer,
    node_dependency_analyzer,
)
import logging

logger = logging.getLogger(__name__)


# ── Node 1: preprocess ────────────────────────────────────────────────────────

def node_preprocess(state: ScanStateV2) -> dict:
    code = state["code"]
    language = state["language"]
    logger.info(f"Preprocessing {language} code ({len(code)} chars)")
    result = preprocess(code, language)
    if result["has_suspicious_comments"]:
        logger.warning(f"Suspicious comments: {result['flagged_comments']}")
    return {"preprocess_result": result}


# ── Node 6: synthesizer ───────────────────────────────────────────────────────

def node_synthesizer(state: ScanStateV2) -> dict:
    """
    Pure Python — no AI call.
    Combines all findings, deduplicates, calculates risk score.
    """
    all_findings = (
        state.get("injection_findings", []) +
        state.get("auth_findings", []) +
        state.get("secrets_findings", []) +
        state.get("dependency_findings", [])
    )

    # Deduplicate by rule_id — keep highest confidence
    seen = {}
    for f in all_findings:
        rule_id = f["rule_id"]
        if rule_id not in seen:
            seen[rule_id] = f
        else:
            # Keep higher confidence finding
            confidence_rank = {"high": 3, "medium": 2, "low": 1}
            existing = confidence_rank.get(seen[rule_id]["confidence"], 0)
            incoming = confidence_rank.get(f["confidence"], 0)
            if incoming > existing:
                seen[rule_id] = f

    deduped = list(seen.values())

    # Calculate risk score
    score = 0
    for f in deduped:
        if f["severity"] == "High":   score += 3
        if f["severity"] == "Medium": score += 2
        if f["severity"] == "Low":    score += 1
    score = min(score, 10)

    risk_level = "High" if score >= 7 else "Medium" if score >= 4 else "Low"

    logger.info(f"Synthesizer: {len(deduped)} unique findings, score={score}, level={risk_level}")

    return {
        "all_findings": deduped,
        "risk_score": score,
        "risk_level": risk_level,
    }


# ── Node 7: format_output ─────────────────────────────────────────────────────

def node_format_output(state: ScanStateV2) -> dict:
    """
    Pure Python — no AI call.
    Separates low-confidence findings into needs_human_review.
    Builds final report string.
    """
    all_findings = state.get("all_findings", [])

    # Split by confidence
    confirmed = [f for f in all_findings if f["confidence"] in ("high", "medium")]
    needs_review = [f for f in all_findings if f["confidence"] == "low"]

    # Build report
    if not all_findings:
        report = "No security vulnerabilities detected."
    else:
        lines = []
        lines.append(f"## Security Analysis Report")
        lines.append(f"**Risk Score:** {state.get('risk_score', 0)}/10")
        lines.append(f"**Risk Level:** {state.get('risk_level', 'Low')}")
        lines.append(f"**Total Findings:** {len(all_findings)}")
        lines.append("")

        if confirmed:
            lines.append("### Confirmed Findings")
            for f in confirmed:
                lines.append(f"**{f['rule_id']}** ({f['severity']})")
                lines.append(f"- Where: {f['line_hint']}")
                lines.append(f"- Issue: {f['description']}")
                lines.append(f"- Fix: {f['remediation']}")
                lines.append("")

        if needs_review:
            lines.append("### Needs Human Review (Low Confidence)")
            for f in needs_review:
                lines.append(f"**{f['rule_id']}** ({f['severity']})")
                lines.append(f"- Where: {f['line_hint']}")
                lines.append(f"- Issue: {f['description']}")
                lines.append("")

        report = "\n".join(lines)

    return {
        "report": report,
        "needs_human_review": needs_review,
    }


# ── Graph ─────────────────────────────────────────────────────────────────────

def build_graph_v2():
    g = StateGraph(ScanStateV2)

    g.add_node("preprocess",          node_preprocess)
    g.add_node("injection_analyzer",  node_injection_analyzer)
    g.add_node("auth_analyzer",       node_auth_analyzer)
    g.add_node("secrets_analyzer",    node_secrets_analyzer)
    g.add_node("dependency_analyzer", node_dependency_analyzer)
    g.add_node("synthesizer",         node_synthesizer)
    g.add_node("format_output",       node_format_output)

    g.set_entry_point("preprocess")

    g.add_edge("preprocess",          "injection_analyzer")
    g.add_edge("preprocess",          "auth_analyzer")
    g.add_edge("preprocess",          "secrets_analyzer")
    g.add_edge("preprocess",          "dependency_analyzer")

    g.add_edge("injection_analyzer",  "synthesizer")
    g.add_edge("auth_analyzer",       "synthesizer")
    g.add_edge("secrets_analyzer",    "synthesizer")
    g.add_edge("dependency_analyzer", "synthesizer")

    g.add_edge("synthesizer",         "format_output")
    g.add_edge("format_output",       END)

    return g.compile()


security_graph_v2 = build_graph_v2()