import streamlit as st
import requests
import os

# Backend URL - uses env var in production, localhost in development
BACKEND_URL = os.getenv("https://secureguard-backend.jollyhill-a64c45f6.eastus.azurecontainerapps.io/", "http://127.0.0.1:8002")

st.set_page_config(
    page_title="SecureGuard",
    page_icon="🛡️",
    layout="wide"
)

st.title(" SecureGuard")
st.subheader("Developer Security Review Assistant")
st.sidebar.title(" Scan History")

if st.sidebar.button("Reset History", type="primary"):
    try:
        requests.delete(f"{BACKEND_URL}/history/reset")
        st.sidebar.success("History cleared.")
        st.rerun()
    except Exception as e:
        st.sidebar.error(f"Failed to reset: {str(e)}")

code = st.text_area(
    "Paste Code Here",
    height=300,
    placeholder="Paste your Python code here..."
)

if st.button("Analyze"):

    if not code.strip():
        st.warning("Please enter some code.")
        st.stop()

    try:

        response = requests.post(
            f"{BACKEND_URL}/analyze",
            json={"code": code}
        )

        result = response.json()

        st.divider()

        # ==========================
        # Risk Assessment Section
        # ==========================

        st.header("📊 Risk Assessment")

        risk_score = result.get("risk_score", 0)
        risk_level = result.get("risk_level", "Unknown")

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                label="Risk Score",
                value=f"{risk_score}/10"
            )

        with col2:
            st.metric(
                label="Risk Level",
                value=risk_level
            )

        if risk_level.lower() == "high":
            st.error("🚨 Overall Risk: HIGH")

        elif risk_level.lower() == "medium":
            st.warning("⚠️ Overall Risk: MEDIUM")

        else:
            st.success("✅ Overall Risk: LOW")

        st.divider()

        # ==========================
        # Findings Section
        # ==========================

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

                if "matched_pattern" in finding:
                    message += (
                        f"  \nMatched Pattern: "
                        f"`{finding['matched_pattern']}`"
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

        # ==========================
        # Security Report Section
        # ==========================

        st.header("📋 Security Report")

        report = result.get("report", "")

        report = report.replace("\\n", "\n")

        st.markdown(report)

    except Exception as e:
        st.error(f"Error: {str(e)}")

try:

    history_response = requests.get(
        f"{BACKEND_URL}/history"
    )

    history = history_response.json()

    if history:

        history_table = []

        for scan in history:

            history_table.append(
                {
                    "ID": scan["id"],
                    "Risk": scan["risk_level"],
                    "Score": scan["risk_score"]
                }
            )

        st.sidebar.dataframe(
            history_table,
            use_container_width=True
        )

except:
    st.sidebar.warning(
        "History unavailable."
    )