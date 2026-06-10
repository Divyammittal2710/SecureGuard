# backend/security_graph_v2.py
from langgraph.graph import StateGraph, END
from graph_state_v2 import ScanStateV2
from preprocessor import preprocess
import logging

logger = logging.getLogger(__name__)


# ── Node 1: preprocess ────────────────────────────────────────────────────────

def node_preprocess(state: ScanStateV2) -> dict:
    """
    Runs BEFORE any AI call.
    - Strips ALL comments (prevents prompt injection via comments)
    - Flags suspicious comments for the attack log
    - Extracts imports for dependency analyzer
    - Normalizes whitespace
    """
    code = state["code"]
    language = state["language"]

    logger.info(f"Preprocessing {language} code ({len(code)} chars)")

    result = preprocess(code, language)

    # Log if suspicious comments were found
    if result["has_suspicious_comments"]:
        logger.warning(
            f"Suspicious comments detected: {result['flagged_comments']}"
        )

    return {"preprocess_result": result}


# ── Nodes 2-5: analyzer placeholders ─────────────────────────────────────────

def node_injection_analyzer(state: ScanStateV2) -> dict:
    """
    Specialist: ONLY injection vulnerabilities.
    OWASP rules: A03 SQL, A03 Command, LLM01, LLM05
    """
    return {"injection_findings": []}  # built Wednesday


def node_auth_analyzer(state: ScanStateV2) -> dict:
    """
    Specialist: ONLY authentication vulnerabilities.
    OWASP rules: A01, A07, A02 weak crypto
    """
    return {"auth_findings": []}  # built Wednesday


def node_secrets_analyzer(state: ScanStateV2) -> dict:
    """
    Specialist: ONLY hardcoded secrets.
    OWASP rules: A02 hardcoded, LLM02, LLM07
    """
    return {"secrets_findings": []}  # built Wednesday


def node_dependency_analyzer(state: ScanStateV2) -> dict:
    """
    Specialist: ONLY dependency risks.
    OWASP rules: A06, A08, LLM03
    """
    return {"dependency_findings": []}  # built Wednesday


# ── Node 6: synthesizer ───────────────────────────────────────────────────────

def node_synthesizer(state: ScanStateV2) -> dict:
    """
    Pure Python — no AI call.
    Combines all findings, deduplicates, scores.
    """
    return {
        "all_findings": [],
        "risk_score": 0,
        "risk_level": "Low",
    }  # built Thursday


# ── Node 7: format_output ─────────────────────────────────────────────────────

def node_format_output(state: ScanStateV2) -> dict:
    """
    Pure Python — no AI call.
    Formats final structured JSON, flags low-confidence findings.
    """
    return {
        "report": "{}",
        "needs_human_review": [],
    }  # built Thursday


# ── Graph ─────────────────────────────────────────────────────────────────────

def build_graph_v2():
    g = StateGraph(ScanStateV2)

    # Register all nodes
    g.add_node("preprocess",          node_preprocess)
    g.add_node("injection_analyzer",  node_injection_analyzer)
    g.add_node("auth_analyzer",       node_auth_analyzer)
    g.add_node("secrets_analyzer",    node_secrets_analyzer)
    g.add_node("dependency_analyzer", node_dependency_analyzer)
    g.add_node("synthesizer",         node_synthesizer)
    g.add_node("format_output",       node_format_output)

    # Entry point
    g.set_entry_point("preprocess")

    # preprocess feeds ALL 4 analyzers
    g.add_edge("preprocess",          "injection_analyzer")
    g.add_edge("preprocess",          "auth_analyzer")
    g.add_edge("preprocess",          "secrets_analyzer")
    g.add_edge("preprocess",          "dependency_analyzer")

    # All 4 analyzers feed synthesizer
    g.add_edge("injection_analyzer",  "synthesizer")
    g.add_edge("auth_analyzer",       "synthesizer")
    g.add_edge("secrets_analyzer",    "synthesizer")
    g.add_edge("dependency_analyzer", "synthesizer")

    # synthesizer → format_output → END
    g.add_edge("synthesizer",         "format_output")
    g.add_edge("format_output",       END)

    return g.compile()


security_graph_v2 = build_graph_v2()