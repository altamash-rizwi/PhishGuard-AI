"""
pytest configuration for PhishGuard AI tests.

Ensures:
  - FLASK_SECRET is set before the app module is imported (so the
    InconsistentVersionWarning from a stale cached import is not triggered).
  - The app module is imported cleanly in each fresh process.
"""
import os
import sys

# Set before any app import so the secret-key warning does not fire.
os.environ.setdefault("FLASK_SECRET", "pytest-test-secret-not-for-production")
