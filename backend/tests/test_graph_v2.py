# backend/tests/test_graph_v2.py
"""
Integration test for SecureGuard v2 graph.
Tests the full pipeline end to end.
Run with: python -m pytest tests/test_graph_v2.py -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_graph_v2 import security_graph_v2


VULNERABLE_CODE = """
import pickle
import os

password = "admin123"
api_key = "sk-abc123secretkey"

def login(username, password):
    query = "SELECT * FROM users WHERE user='" + username + "'"
    os.system(f"log_login {username}")
    if password == "admin123":
        return True

def load_data(data):
    return pickle.loads(data)
"""


def test_full_pipeline_runs():
    result = security_graph_v2.invoke({
        "code": VULNERABLE_CODE,
        "language": "python"
    })
    assert result is not None


def test_pipeline_returns_findings():
    result = security_graph_v2.invoke({
        "code": VULNERABLE_CODE,
        "language": "python"
    })
    assert len(result["all_findings"]) > 0


def test_pipeline_returns_risk_score():
    result = security_graph_v2.invoke({
        "code": VULNERABLE_CODE,
        "language": "python"
    })
    assert result["risk_score"] > 0
    assert result["risk_level"] in ("Low", "Medium", "High")


def test_pipeline_returns_report():
    result = security_graph_v2.invoke({
        "code": VULNERABLE_CODE,
        "language": "python"
    })
    assert len(result["report"]) > 0


def test_clean_code_returns_low_risk():
    clean_code = """
def add(a: int, b: int) -> int:
    return a + b
"""
    result = security_graph_v2.invoke({
        "code": clean_code,
        "language": "python"
    })
    assert result["risk_level"] == "Low"
    assert result["risk_score"] == 0


def test_preprocess_result_present():
    result = security_graph_v2.invoke({
        "code": VULNERABLE_CODE,
        "language": "python"
    })
    assert result["preprocess_result"] is not None
    assert "cleaned_code" in result["preprocess_result"]
    assert "imports" in result["preprocess_result"]