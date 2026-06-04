import os

from dotenv import load_dotenv
from google import genai

# Load environment variables
load_dotenv()

# Initialize Gemini client
client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)


def simple_test():
    """
    Simple test to verify Gemini API connectivity.
    """

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents="Say hello"
        )

        return response.text

    except Exception as e:
        return f"Gemini Error: {str(e)}"


def analyze_with_gemini(code, findings):
    """
    Generate a security report using Gemini.
    """

    if not findings:
        return """
# No Critical Findings

No obvious OWASP vulnerabilities were detected by the rule engine.

## Note

This does not guarantee that the code is completely secure.
Manual review may still uncover vulnerabilities that pattern matching cannot detect.
"""

    findings_text = "\n".join(
        [
            f"""
Issue: {finding['name']}
OWASP: {finding['owasp']}
Severity: {finding['severity']}
"""
            for finding in findings
        ]
    )

    prompt = f"""
You are a senior application security engineer.

The rule engine detected the following findings:

{findings_text}

Analyze the following code:

```python
{code}
```

Return your answer in Markdown format.

Use these EXACT headings:

Vulnerability
OWASP Category
Severity
Risk Explanation
Attack Scenario
Recommended Fix
Secure Code Example

Instructions:

Keep explanations concise and developer-friendly.
Explain why the vulnerability is dangerous.
Give a realistic attack scenario.
Suggest practical remediation.
Provide secure replacement code.
Wrap code examples inside markdown code blocks.
Do not add unnecessary introductions.
Do not add unnecessary conclusions.
"""

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        return response.text

    except Exception as e:
        return f"Gemini Error: {str(e)}"