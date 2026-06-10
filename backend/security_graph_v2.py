# backend/security_graph_v2.py
from langgraph.graph import StateGraph, END
from graph_state_v2 import ScanStateV2


# ── Nodes ────────────────────────────────────────────────────────────────────
# Each node is a placeholder for now.
# Tuesday: preprocess
# Wednesday: all 4 analyzers
# Thursday: synthesizer + format_output

def node_preprocess(state: ScanStateV2) -> dict:
    """
    Runs BEFORE any AI call.
    - Strips/flags comment-based prompt injection attempts
    - Normalizes whitespace
    - Extracts imports and dependencies
    - Output: cleaned code + metadata
    """
    pass  # built Tuesday


def node_injection_analyzer(state: ScanStateV2) -> dict:
    """
    Specialist: ONLY injection vulnerabilities.
    OWASP rules: A03 SQL, A03 Command, LLM01, LLM05
    Returns structured findings JSON.
    """
    pass  # built Wednesday


def node_auth_analyzer(state: ScanStateV2) -> dict:
    """
    Specialist: ONLY authentication vulnerabilities.
    OWASP rules: A01, A07, A02 weak crypto
    Returns structured findings JSON.
    """
    pass  # built Wednesday


def node_secrets_analyzer(state: ScanStateV2) -> dict:
    """
    Specialist: ONLY hardcoded secrets.
    OWASP rules: A02 hardcoded, LLM02, LLM07
    Returns structured findings JSON.
    """
    pass  # built Wednesday


def node_dependency_analyzer(state: ScanStateV2) -> dict:
    """
    Specialist: ONLY dependency risks.
    OWASP rules: A06, A08, LLM03
    Returns structured findings JSON.
    """
    pass  # built Wednesday


def node_synthesizer(state: ScanStateV2) -> dict:
    """
    No AI call — pure Python.
    - Combines findings from all 4 analyzers
    - Deduplicates overlapping findings
    - Calculates overall risk score
    """
    pass  # built Thursday


def node_format_output(state: ScanStateV2) -> dict:
    """
    No AI call — pure Python.
    - Formats final structured JSON response
    - Flags low-confidence findings as needs_human_review
    """
    pass  # built Thursday


# ── Graph ────────────────────────────────────────────────────────────────────

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

    # Entry point — always starts here
    g.set_entry_point("preprocess")

    # preprocess feeds ALL 4 analyzers
    g.add_edge("preprocess",          "injection_analyzer")
    g.add_edge("preprocess",          "auth_analyzer")
    g.add_edge("preprocess",          "secrets_analyzer")
    g.add_edge("preprocess",          "dependency_analyzer")

    # All 4 analyzers feed into synthesizer
    g.add_edge("injection_analyzer",  "synthesizer")
    g.add_edge("auth_analyzer",       "synthesizer")
    g.add_edge("secrets_analyzer",    "synthesizer")
    g.add_edge("dependency_analyzer", "synthesizer")

    # synthesizer → format_output → END
    g.add_edge("synthesizer",         "format_output")
    g.add_edge("format_output",       END)

    return g.compile()


security_graph_v2 = build_graph_v2()