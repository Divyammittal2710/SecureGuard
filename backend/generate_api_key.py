# generate_api_key.py
# ---------------------------------------------------------------
# Run this once to create an API key for a developer.
# The raw key is shown ONCE — copy it immediately.
# Only the hash is stored in the database.
#
# Usage:  python generate_api_key.py <label>
# Example: python generate_api_key.py divyam-dev
# ---------------------------------------------------------------

import sys
import secrets
from database import init_db, store_api_key

def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "default"

    init_db()

    raw_key = secrets.token_urlsafe(32)
    store_api_key(label, raw_key)

    print("\n" + "=" * 55)
    print(f"  API Key generated for: {label}")
    print("=" * 55)
    print(f"\n  {raw_key}\n")
    print("  ⚠️  Copy this now — it will NOT be shown again.")
    print("  Store it in your .env as: API_KEY=<value>")
    print("=" * 55 + "\n")

if __name__ == "__main__":
    main()