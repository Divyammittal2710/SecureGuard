# frontend/streamlit_app.py
import streamlit as st
import requests
import os

BACKEND_URL = os.getenv(
    "BACKEND_URL",
    "https://secureguard-backend.jollyhill-a64c45f6.eastus.azurecontainerapps.io"
)

API_KEY = os.getenv("API_KEY", "")
HEADERS = {"X-API-Key": API_KEY}

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
ADMIN_HEADERS = {"X-API-Key": ADMIN_API_KEY}

LANGUAGES = [
    "python", "javascript", "java", "typescript",
    "go", "rust", "cpp", "c", "ruby", "php"
]

st.set_page_config(
    page_title="SecureGuard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SecureGuard")
st.subheader("Developer Security Review Assistant")
st.sidebar.title("🕓 Scan History")

if st.sidebar.button("Reset History", type="primary"):
    try:
        requests.delete(
            f"{BACKEND_URL}/history/reset",
            headers=ADMIN_HEADERS
        )
        st.sidebar.success("History cleared.")
        st.rerun()
    except Exception as e:
        st.sidebar.error(f"Failed to reset: {str(e)}")

# Language selector
language = st.selectbox(
    "Select Language",
    options=LANGUAGES,
    index=0
)

code = st.text_area(
    "Paste Code Here",
    height=300,
    placeholder=f"Paste your {language} code here..."
)

# Language mismatch detection
if code.strip():
    try:
        detect_response = requests.post(
            f"{BACKEND_URL}/detect-language",
            json={"code": code, "language": language},
            headers=HEADERS
        )
        if detect_response.status_code == 200:
            detect_result = detect_response.json()
            if not detect_result["match"] and detect_result["detected"] != "unknown":
                st.warning(
                    f"⚠️ Detected language: **{detect_result['detected'].upper()}** "
                    f"but you selected: **{language.upper()}**. "
                    f"Consider changing the language for more accurate analysis."
                )
    except:
        pass

if st.button("Analyze"):

    if not code.strip():
        st.warning("Please enter some code.")
        st.stop()

    try:
        response = requests.post(
            f"{BACKEND_URL}/analyze",
            json={"code": code, "language": language},
            headers=HEADERS,
            timeout=120.0  # v2 makes 4 AI calls — needs more time
        )

        if response.status_code == 401:
            st.error("❌ Unauthorized — API key missing or invalid.")
            st.stop()

        if response.status_code == 422:
            st.error("❌ Invalid input — code may be too long, wrong language, or malformed.")
            st.stop()

        if response.status_code == 429:
            st.error("⏱️ Rate limit exceeded — please wait and try again.")
            st.stop()

        result = response.json()

        st.divider()

        # ── Prompt Injection Warning ──────────────────────────────────────
        preprocess = result.get("preprocess_result", {})
        if preprocess:
            has_suspicious = preprocess.get("has_suspicious_comments", False)
            flagged_comments = preprocess.get("flagged_comments", [])
            flagged_strings = preprocess.get("flagged_strings", [])
            stripped_docstrings = preprocess.get("stripped_docstrings", [])

            if has_suspicious:
                st.error(
                    "🚨 **Prompt Injection Attempt Detected** — "
                    "Suspicious content found in your code and stripped before analysis. "
                    "Your code was still analyzed for real vulnerabilities."
                )
                if flagged_comments:
                    with st.expander("View flagged comments"):
                        for c in flagged_comments:
                            st.code(c)
                if flagged_strings:
                    with st.expander("View flagged string literals"):
                        for s in flagged_strings:
                            st.code(s)
                if stripped_docstrings:
                    with st.expander("View stripped docstrings"):
                        for d in stripped_docstrings:
                            st.code(d)

        # ── Risk Assessment ───────────────────────────────────────────────
        st.header("📊 Risk Assessment")

        risk_score = result.get("risk_score", 0)
        risk_level = result.get("risk_level", "Unknown")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(label="Risk Score", value=f"{risk_score}/10")
        with col2:
            st.metric(label="Risk Level", value=risk_level)
        with col3:
            st.metric(label="Language", value=language.upper())

        if risk_level.lower() == "high":
            st.error("🚨 Overall Risk: HIGH")
        elif risk_level.lower() == "medium":
            st.warning("⚠️ Overall Risk: MEDIUM")
        else:
            st.success("✅ Overall Risk: LOW")

        st.divider()

        # ── Confirmed Findings ────────────────────────────────────────────
        st.header("🔍 Detected Findings")

        findings = result.get("findings", [])
        needs_review = result.get("needs_human_review", [])

        # Separate confirmed from needs_review
        confirmed = [f for f in findings if f not in needs_review]

        if confirmed:
            st.subheader("Confirmed Findings")
            for finding in confirmed:
                severity = finding.get("severity", "Unknown")
                confidence = finding.get("confidence", "")
                message = (
                    f"**{finding.get('rule_id')}**  \n"
                    f"Category: {finding.get('category', '')}  \n"
                    f"Where: {finding.get('line_hint', '')}  \n"
                    f"Severity: {severity}  |  Confidence: {confidence}"
                )
                if severity.lower() == "high":
                    st.error(message)
                elif severity.lower() == "medium":
                    st.warning(message)
                else:
                    st.info(message)
        else:
            st.success("✅ No confirmed findings.")

        # ── Needs Human Review ────────────────────────────────────────────
        if needs_review:
            st.subheader("⚠️ Needs Human Review (Low Confidence)")
            st.caption("These findings have low confidence — a human should verify them.")
            for finding in needs_review:
                severity = finding.get("severity", "Unknown")
                message = (
                    f"**{finding.get('rule_id')}**  \n"
                    f"Where: {finding.get('line_hint', '')}  \n"
                    f"Severity: {severity}  |  Confidence: low"
                )
                st.warning(message)

        st.divider()

        # ── Security Report ───────────────────────────────────────────────
        st.header("📋 Security Report")

        report = result.get("report", "")
        report = report.replace("\\n", "\n")
        st.markdown(report)

    except Exception as e:
        st.error(f"Error: {str(e)}")

# ── Sidebar History ───────────────────────────────────────────────────────────
try:
    history_response = requests.get(
        f"{BACKEND_URL}/history",
        headers=HEADERS
    )
    history = history_response.json()

    if history:
        history_table = [
            {"ID": scan["id"], "Risk": scan["risk_level"], "Score": scan["risk_score"]}
            for scan in history
        ]
        st.sidebar.dataframe(history_table, use_container_width=True)

except:
    st.sidebar.warning("History unavailable.")