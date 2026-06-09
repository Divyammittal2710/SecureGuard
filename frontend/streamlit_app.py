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
    index=0  # defaults to python
)

code = st.text_area(
    "Paste Code Here",
    height=300,
    placeholder=f"Paste your {language} code here..."
)

if st.button("Analyze"):

    if not code.strip():
        st.warning("Please enter some code.")
        st.stop()

    try:
        response = requests.post(
            f"{BACKEND_URL}/analyze",
            json={"code": code, "language": language},
            headers=HEADERS
        )

        if response.status_code == 401:
            st.error("❌ Unauthorized — API key missing or invalid.")
            st.stop()

        if response.status_code == 422:
            st.error("❌ Invalid input — code may be too long, wrong language, or malformed.")
            st.stop()

        if response.status_code == 429:
            st.error("⏱️ Rate limit exceeded — please wait a minute and try again.")
            st.stop()

        result = response.json()

        st.divider()

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

        st.header("🔍 Detected Findings")

        findings = result.get("findings", [])

        if findings:
            for finding in findings:
                severity = finding.get("severity", "Unknown")
                message = (
                    f"**{finding.get('name')}**  \n"
                    f"OWASP: {finding.get('owasp')}  \n"
                    f"Severity: {severity}"
                )
                if severity.lower() == "high":
                    st.error(message)
                elif severity.lower() == "medium":
                    st.warning(message)
                else:
                    st.info(message)
        else:
            st.success("✅ No OWASP findings detected.")

        st.divider()

        st.header("📋 Security Report")

        report = result.get("report", "")
        report = report.replace("\\n", "\n")
        st.markdown(report)

    except Exception as e:
        st.error(f"Error: {str(e)}")

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