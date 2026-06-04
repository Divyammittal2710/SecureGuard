from gemini_service import analyze_with_gemini

code = '''
password = "admin123"
'''

findings = [
    {
        "name": "Hardcoded Secret",
        "owasp": "A02:2021",
        "severity": "Medium"
    }
]

report = analyze_with_gemini(
    code,
    findings
)

print(report)