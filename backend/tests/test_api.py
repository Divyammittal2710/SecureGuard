# backend/tests/test_api.py
"""
SecureGuard API Test Suite
Week 2 Weekend Task — httpx test suite covering all edge cases.

Run with:
    pip install httpx pytest
    pytest backend/tests/test_api.py -v
"""

import httpx
import pytest

# ---------------------------------------------------------------------------
# Config — change BASE_URL to http://127.0.0.1:8002 for local testing
# ---------------------------------------------------------------------------
BASE_URL = "https://secureguard-backend.jollyhill-a64c45f6.eastus.azurecontainerapps.io"
API_KEY = "JBqa1ZWMEn2WPhgJvGifFN1_UkxjGBuGdzdfcFNL_ZI"
ADMIN_KEY = "17db94a7ad0c4f25ec3f24ab74cdfdf5c3b49d7c2ea65e86b4fa866d914ab764"

VALID_HEADERS = {"X-API-Key": API_KEY}
ADMIN_HEADERS = {"X-API-Key": ADMIN_KEY}

VALID_CODE = """
def login(user, pwd):
    query = "SELECT * FROM users WHERE user='" + user + "'"
    password = "admin123"
"""

# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

def test_health_check():
    """GET / should return 200 with SecureGuard Running message."""
    response = httpx.get(f"{BASE_URL}/")
    assert response.status_code == 200
    assert response.json()["message"] == "SecureGuard Running"


# ---------------------------------------------------------------------------
# Authentication Tests
# ---------------------------------------------------------------------------

def test_missing_api_key():
    """POST /analyze without API key should return 401."""
    response = httpx.post(
        f"{BASE_URL}/analyze",
        json={"code": VALID_CODE, "language": "python"}
    )
    assert response.status_code == 401
    body = response.json()
    assert body["error"] == "unauthorized"
    assert "message" in body
    # Must not expose internal details
    assert "stack" not in str(body)
    assert "traceback" not in str(body).lower()


def test_invalid_api_key():
    """POST /analyze with wrong API key should return 401."""
    response = httpx.post(
        f"{BASE_URL}/analyze",
        json={"code": VALID_CODE, "language": "python"},
        headers={"X-API-Key": "wrongkey123"}
    )
    assert response.status_code == 401
    body = response.json()
    assert body["error"] == "unauthorized"
    # Same message for missing and invalid — prevents enumeration
    assert body["message"] == "Invalid or missing API key"


def test_history_missing_api_key():
    """GET /history without API key should return 401."""
    response = httpx.get(f"{BASE_URL}/history")
    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


def test_admin_reset_with_regular_key():
    """DELETE /history/reset with regular key should return 403."""
    response = httpx.delete(
        f"{BASE_URL}/history/reset",
        headers=VALID_HEADERS
    )
    assert response.status_code == 403
    assert response.json()["error"] == "forbidden"


def test_admin_reset_with_admin_key():
    """DELETE /history/reset with admin key should return 200."""
    response = httpx.delete(
        f"{BASE_URL}/history/reset",
        headers=ADMIN_HEADERS
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Scan history cleared"


# ---------------------------------------------------------------------------
# Input Validation Tests
# ---------------------------------------------------------------------------

def test_valid_submission():
    """POST /analyze with valid code and language should return 200."""
    response = httpx.post(
        f"{BASE_URL}/analyze",
        json={"code": VALID_CODE, "language": "python"},
        headers=VALID_HEADERS,
        timeout=60.0
    )
    assert response.status_code == 200
    body = response.json()
    assert "findings" in body
    assert "risk_score" in body
    assert "risk_level" in body
    assert "report" in body
    assert isinstance(body["risk_score"], int)
    assert body["risk_level"] in ["Low", "Medium", "High"]


def test_oversized_submission():
    """POST /analyze with code > 20000 chars should return 422."""
    response = httpx.post(
        f"{BASE_URL}/analyze",
        json={"code": "x" * 20001, "language": "python"},
        headers=VALID_HEADERS
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "validation_error"
    assert "details" in body


def test_empty_code():
    """POST /analyze with empty code should return 422."""
    response = httpx.post(
        f"{BASE_URL}/analyze",
        json={"code": "", "language": "python"},
        headers=VALID_HEADERS
    )
    assert response.status_code == 422
    assert response.json()["error"] == "validation_error"


def test_missing_language():
    """POST /analyze without language field should return 422."""
    response = httpx.post(
        f"{BASE_URL}/analyze",
        json={"code": VALID_CODE},
        headers=VALID_HEADERS
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "validation_error"
    assert any("language" in d["field"] for d in body["details"])


def test_invalid_language():
    """POST /analyze with unsupported language should return 422."""
    response = httpx.post(
        f"{BASE_URL}/analyze",
        json={"code": VALID_CODE, "language": "cobol"},
        headers=VALID_HEADERS
    )
    assert response.status_code == 422
    assert response.json()["error"] == "validation_error"


def test_binary_content():
    """POST /analyze with binary content should return 422."""
    binary_code = bytes(range(256)).decode("latin-1")
    response = httpx.post(
        f"{BASE_URL}/analyze",
        json={"code": binary_code, "language": "python"},
        headers=VALID_HEADERS
    )
    assert response.status_code == 422
    assert response.json()["error"] == "validation_error"


def test_null_bytes_stripped():
    """POST /analyze with null bytes should succeed — null bytes are stripped."""
    code_with_nulls = "password = 'admin123'\x00"
    response = httpx.post(
        f"{BASE_URL}/analyze",
        json={"code": code_with_nulls, "language": "python"},
        headers=VALID_HEADERS,
        timeout=60.0
    )
    # Should succeed — null bytes are stripped not rejected
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Language Detection Tests
# ---------------------------------------------------------------------------

def test_detect_language_match():
    """POST /detect-language with matching language should return match=true."""
    response = httpx.post(
        f"{BASE_URL}/detect-language",
        json={"code": VALID_CODE, "language": "python"},
        headers=VALID_HEADERS
    )
    assert response.status_code == 200
    body = response.json()
    assert body["detected"] == "python"
    assert body["submitted"] == "python"
    assert body["match"] is True


def test_detect_language_mismatch():
    """POST /detect-language with wrong language should return match=false."""
    js_code = "const x = require('express')\nconsole.log(x)"
    response = httpx.post(
        f"{BASE_URL}/detect-language",
        json={"code": js_code, "language": "python"},
        headers=VALID_HEADERS
    )
    assert response.status_code == 200
    body = response.json()
    assert body["detected"] == "javascript"
    assert body["match"] is False


# ---------------------------------------------------------------------------
# Error Response Structure Tests
# ---------------------------------------------------------------------------

def test_error_responses_have_no_stack_traces():
    """All error responses must not contain stack traces or internal paths."""
    response = httpx.post(
        f"{BASE_URL}/analyze",
        json={"code": VALID_CODE, "language": "python"}
        # No API key — triggers 401
    )
    body = str(response.json())
    assert "traceback" not in body.lower()
    assert "file " not in body.lower()
    assert "line " not in body.lower()
    assert "azure" not in body.lower()
    assert ".py" not in body.lower()


def test_docs_disabled_in_production():
    """/docs should return 404 in production (DEBUG=false)."""
    response = httpx.get(f"{BASE_URL}/docs")
    assert response.status_code == 404


def test_redoc_disabled_in_production():
    """/redoc should return 404 in production."""
    response = httpx.get(f"{BASE_URL}/redoc")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# History Tests
# ---------------------------------------------------------------------------

def test_valid_history_fetch():
    """GET /history with valid API key should return 200 with a list."""
    response = httpx.get(
        f"{BASE_URL}/history",
        headers=VALID_HEADERS
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_history_response_structure():
    """GET /history items should have id, risk_score, risk_level, created_at."""
    response = httpx.get(
        f"{BASE_URL}/history",
        headers=VALID_HEADERS
    )
    assert response.status_code == 200
    history = response.json()
    if history:
        item = history[0]
        assert "id" in item
        assert "risk_score" in item
        assert "risk_level" in item
        assert "created_at" in item