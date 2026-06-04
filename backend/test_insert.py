from database import save_scan

save_scan(
    code="print('hello')",
    findings="[]",
    risk_score=0,
    risk_level="Low",
    report="No issues found"
)

print("Scan saved.")