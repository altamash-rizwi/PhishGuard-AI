"""pytest configuration for PhishGuard AI (root tests/ directory).
Sets FLASK_SECRET before any app import so the dev-fallback warning does not
appear during testing.
"""
import os
os.environ.setdefault("FLASK_SECRET", "pytest-test-secret-not-for-production")
