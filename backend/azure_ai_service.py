import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Initialize Azure AI Foundry client
client = OpenAI(
    base_url=os.getenv("PROJECT_ENDPOINT") + "/openai",
    api_key=os.getenv("AZURE_API_KEY"),
    default_query={"api-version": "2025-01-01-preview"}
)

MODEL = os.getenv("MODEL_DEPLOYMENT_NAME", "gpt-5-mini")


def simple_test():
    """
    Simple test to verify Azure AI connectivity.
    """
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": "Say hello"}]
        )
        return response.choices[0].message.content

    except Exception as e:
        return f"Azure AI Error: {str(e)}"


def analyze_with_azure(code, findings):
    """
    Generate a security report using Azure AI Foundry (gpt-5-mini).
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
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior application security engineer. Respond in Markdown format only."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        return response.choices[0].message.content

    except Exception as e:
        return f"Azure AI Error: {str(e)}"