from langgraph.graph import StateGraph, END

from graph_state import ScanState
from graph_nodes import node_scan, node_analyze, node_save


def route_after_scan(state: ScanState) -> str:
    if state["findings"]:
        return "analyze"
    return "save"


def build_graph():
    g = StateGraph(ScanState)

    g.add_node("scan", node_scan)
    g.add_node("analyze", node_analyze)
    g.add_node("save", node_save)

    g.set_entry_point("scan")

    g.add_conditional_edges(
        "scan",
        route_after_scan,
        {
            "analyze": "analyze",
            "save": "save",
        },
    )

    g.add_edge("analyze", "save")
    g.add_edge("save", END)

    return g.compile()


security_graph = build_graph()
