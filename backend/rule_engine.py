import json


def load_rules():

    with open("rules/owasp_rules.json") as f:
        return json.load(f)


def scan_code(code):

    findings = []

    rules = load_rules()

    for rule in rules:

        for pattern in rule["patterns"]:

            if pattern.lower() in code.lower():

                findings.append(
                    {
                        "rule_id": rule["rule_id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "owasp": rule["owasp_category"]
                    }
                )

                break

    score = calculate_risk_score(findings)

    return {
        "findings": findings,
        "risk_score": score,
        "risk_level": get_risk_level(score)
    }


def calculate_risk_score(findings):

    severity_map = {
        "High": 3,
        "Medium": 2,
        "Low": 1
    }

    raw_score = sum(
        severity_map.get(
            finding["severity"],
            0
        )
        for finding in findings
    )

    return min(raw_score, 10)


def get_risk_level(score):

    if score >= 8:
        return "High"

    elif score >= 4:
        return "Medium"

    return "Low"