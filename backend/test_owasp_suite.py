# test_owasp_suite.py
# ---------------------------------------------------------------
# One concrete vulnerable code snippet per OWASP rule defined in
# rules/owasp_rules.json.  Each snippet is intentionally insecure
# for testing purposes — do NOT use any of this in production.
#
# Run:  python test_owasp_suite.py
# ---------------------------------------------------------------

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from rule_engine import scan_code

PASS = "\033[92m PASS\033[0m"
FAIL = "\033[91m FAIL\033[0m"


# ---------------------------------------------------------------------------
# Test cases: (rule_id, description, vulnerable_snippet)
# ---------------------------------------------------------------------------
TEST_CASES = [

    # A01 — Broken Access Control
    (
        "A01_ACCESS_CONTROL",
        "Sensitive operation with no authorization check",
        """
def delete_user(user_id):
    is_admin = True          # hardcoded privilege escalation
    db.execute(f"DELETE FROM users WHERE id = {user_id}")
""",
    ),

    # A02 — Hardcoded Secret
    (
        "A02_HARDCODED_SECRET",
        "Database password stored directly in source code",
        """
def connect():
    password = "SuperSecret123!"
    return psycopg2.connect(host="db", password=password)
""",
    ),

    # A02 — Weak Cryptography
    (
        "A02_WEAK_CRYPTO",
        "MD5 used to hash a user password",
        """
import hashlib

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
""",
    ),

    # A03 — SQL Injection
    (
        "A03_SQL_INJECTION",
        "User input interpolated directly into SQL query",
        """
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
""",
    ),

    # A03 — Command Injection
    (
        "A03_COMMAND_INJECTION",
        "User-supplied filename passed to os.system",
        """
import os

def convert_file(filename):
    os.system(f"convert {filename} output.pdf")
""",
    ),

    # A04 — Insecure Design
    (
        "A04_INSECURE_DESIGN",
        "Auth bypass flag left in production code",
        """
def process_request(user, action):
    bypass_auth = True
    if bypass_auth or user.is_admin:
        perform_action(action)
""",
    ),

    # A05 — Debug Mode Enabled
    (
        "A05_DEBUG_ENABLED",
        "Flask/Django app started with debug=True",
        """
from flask import Flask
app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
""",
    ),

    # A05 — Permissive CORS
    (
        "A05_CORS_MISCONFIG",
        "CORS wildcard allows any origin",
        """
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
)
""",
    ),

    # A06 — Vulnerable Component
    (
        "A06_VULNERABLE_COMPONENT",
        "Reference to requirements.txt triggers dependency review flag",
        """
# requirements.txt
# django==2.2.0   <- known CVEs
# requests==2.18.0
""",
    ),

    # A07 — Weak Authentication
    (
        "A07_WEAK_AUTH",
        "Plain-text password comparison with hardcoded admin credential",
        """
def login(username, password):
    if username == 'admin' and if password == "letmein":
        return True
    return False
""",
    ),

    # A08 — Insecure Deserialization
    (
        "A08_INSECURE_DESERIALIZATION",
        "Untrusted pickle data loaded from user request",
        """
import pickle

def load_session(data):
    session = pickle.loads(data)   # data comes from cookie
    return session
""",
    ),

    # A09 — Insufficient Logging
    (
        "A09_INSUFFICIENT_LOGGING",
        "Exception swallowed silently with bare except/pass",
        """
def transfer_funds(amount, to_account):
    try:
        bank.transfer(amount, to_account)
    except:
        pass   # failure silently ignored, no audit log
""",
    ),

    # A10 — SSRF
    (
        "A10_SSRF",
        "User-controlled URL fetched without validation",
        """
import requests

def fetch_preview(url):
    response = requests.get(url)   # url comes from user input
    return response.text
""",
    ),

    # LLM01 — Prompt Injection
    (
        "OWASP-LLM01",
        "User input appended directly to LLM prompt",
        """
def ask_llm(user_input):
    prompt = user_input   # attacker controls the full prompt
    response = openai.chat(prompt)
    return response
""",
    ),

    # LLM02 — Sensitive Information Exposure
    (
        "OWASP-LLM02",
        "API key included in context sent to LLM",
        """
def build_context():
    api_key = os.getenv("OPENAI_API_KEY")
    return f"Use this key: {api_key} to call the service."
""",
    ),

    # LLM05 — Unsafe LLM Output Execution
    (
        "OWASP-LLM05",
        "LLM response passed directly to eval()",
        """
def run_generated_code(prompt):
    response = llm.complete(prompt)
    eval(response)   # executes whatever the model returned
""",
    ),

    # LLM06 — Excessive Agent Permissions
    (
        "OWASP-LLM06",
        "LLM agent allowed to execute arbitrary shell commands",
        """
def agent_action(command):
    # LLM decides what command to run
    subprocess.Popen(command, shell=True)
""",
    ),

    # LLM08 — Vector Store Data Leakage
    (
        "OWASP-LLM08",
        "PII embedded into vector store without sanitisation",
        """
def index_customer_data(records):
    for record in records:
        vector_store.add(embedding_model.embed(record["ssn"]))
""",
    ),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_tests():
    passed = 0
    failed = 0
    failures = []

    print("\n" + "=" * 65)
    print("  SecureGuard — OWASP Vulnerability Trigger Test Suite")
    print("=" * 65 + "\n")

    for rule_id, description, snippet in TEST_CASES:
        result = scan_code(snippet)
        matched_ids = {f["rule_id"] for f in result["findings"]}

        if rule_id in matched_ids:
            print(f"{PASS}  [{rule_id}]  {description}")
            passed += 1
        else:
            print(f"{FAIL}  [{rule_id}]  {description}")
            failures.append((rule_id, description))
            failed += 1

    print("\n" + "-" * 65)
    print(f"  Results: {passed} passed, {failed} failed out of {len(TEST_CASES)} tests")
    print("-" * 65 + "\n")

    if failures:
        print("Failed rules (pattern not matched — review owasp_rules.json):")
        for rule_id, desc in failures:
            print(f"  • {rule_id}: {desc}")
        print()

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)