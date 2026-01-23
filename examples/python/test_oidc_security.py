#!/usr/bin/env python3
"""
OIDC-Loki Python Client Example

This example demonstrates how to test a Python OIDC client against
OIDC-Loki's malicious tokens.

Run: python test_oidc_security.py
Prerequisites:
  - OIDC-Loki running on http://localhost:9000
  - pip install pyjwt requests
"""

import base64
import json
import sys
import time
from dataclasses import dataclass
from typing import Optional

import jwt
import requests

LOKI_URL = "http://localhost:9000"
CLIENT_ID = "test-client"
CLIENT_SECRET = "test-secret"


@dataclass
class TestResult:
    name: str
    passed: bool
    message: str


def create_session(name: str, mischief: list[str]) -> Optional[str]:
    """Create a mischief session with Loki."""
    try:
        response = requests.post(
            f"{LOKI_URL}/admin/sessions",
            json={"name": name, "mode": "explicit", "mischief": mischief},
        )
        response.raise_for_status()
        return response.json()["sessionId"]
    except requests.RequestException as e:
        print(f"  SKIP: Could not create session: {e}")
        return None


def get_token(session_id: Optional[str] = None) -> Optional[str]:
    """Request a token from Loki with an optional session ID."""
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic "
        + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode(),
    }
    if session_id:
        headers["X-Loki-Session"] = session_id

    try:
        response = requests.post(
            f"{LOKI_URL}/token",
            headers=headers,
            data={"grant_type": "client_credentials"},
        )
        response.raise_for_status()
        return response.json()["access_token"]
    except requests.RequestException as e:
        print(f"  SKIP: Could not get token: {e}")
        return None


def validate_token(token: str) -> None:
    """
    Validate a token with security checks.

    In production, use a proper OIDC library like authlib or python-jose.
    This example demonstrates the security checks your client should perform.

    Raises:
        ValueError: If the token fails any security check
    """
    # Decode without verification to inspect the token
    try:
        # Get the header without verifying signature
        header = jwt.get_unverified_header(token)
    except jwt.exceptions.DecodeError as e:
        raise ValueError(f"Invalid token format: {e}")

    # Security Check 1: Reject alg:none
    alg = header.get("alg", "").lower()
    if alg == "none":
        raise ValueError("SECURITY: token uses alg:none - unsigned tokens not allowed")

    # Security Check 2: Reject symmetric algorithms (key confusion defense)
    if alg in ("hs256", "hs384", "hs512"):
        raise ValueError(
            f"SECURITY: symmetric algorithm {alg.upper()} not allowed - "
            "possible key confusion attack"
        )

    # Security Check 3: Validate claims (without signature verification for demo)
    try:
        # Decode without verification - in production, ALWAYS verify signatures
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.exceptions.DecodeError as e:
        raise ValueError(f"Invalid token claims: {e}")

    # Check expiration
    exp = claims.get("exp")
    if exp is not None and exp < time.time():
        raise ValueError("SECURITY: token is expired")

    # Check issuer
    iss = claims.get("iss")
    if iss and iss != LOKI_URL:
        raise ValueError(f"SECURITY: unexpected issuer: {iss}")


def test_alg_none() -> TestResult:
    """Test 1: Algorithm None Attack."""
    print("\nTest 1: Algorithm None Attack")
    print("-" * 40)

    session_id = create_session("python-alg-none-test", ["alg-none"])
    if not session_id:
        return TestResult("alg-none", False, "Could not create session")

    token = get_token(session_id)
    if not token:
        return TestResult("alg-none", False, "Could not get token")

    try:
        validate_token(token)
        print("  FAIL: Client accepted alg:none token!")
        return TestResult("alg-none", False, "Client accepted unsigned token")
    except ValueError as e:
        if "alg:none" in str(e):
            print(f"  PASS: Client correctly rejected alg:none token")
            print(f"  Error: {e}")
            return TestResult("alg-none", True, str(e))
        print(f"  PASS: Client rejected token: {e}")
        return TestResult("alg-none", True, str(e))


def test_key_confusion() -> TestResult:
    """Test 2: Key Confusion Attack."""
    print("\nTest 2: Key Confusion Attack")
    print("-" * 40)

    session_id = create_session("python-key-confusion-test", ["key-confusion"])
    if not session_id:
        return TestResult("key-confusion", False, "Could not create session")

    token = get_token(session_id)
    if not token:
        return TestResult("key-confusion", False, "Could not get token")

    try:
        validate_token(token)
        print("  FAIL: Client accepted key confusion token!")
        return TestResult("key-confusion", False, "Client accepted HS256 token")
    except ValueError as e:
        if "key confusion" in str(e).lower() or "symmetric" in str(e).lower():
            print(f"  PASS: Client correctly rejected HS256 token")
            print(f"  Error: {e}")
            return TestResult("key-confusion", True, str(e))
        print(f"  PASS: Client rejected token: {e}")
        return TestResult("key-confusion", True, str(e))


def test_temporal_tampering() -> TestResult:
    """Test 3: Temporal Tampering (Expired Token)."""
    print("\nTest 3: Temporal Tampering (Expired Token)")
    print("-" * 40)

    session_id = create_session("python-temporal-test", ["temporal-tampering"])
    if not session_id:
        return TestResult("temporal-tampering", False, "Could not create session")

    token = get_token(session_id)
    if not token:
        return TestResult("temporal-tampering", False, "Could not get token")

    try:
        validate_token(token)
        print("  FAIL: Client accepted expired token!")
        return TestResult("temporal-tampering", False, "Client accepted expired token")
    except ValueError as e:
        if "expired" in str(e).lower():
            print(f"  PASS: Client correctly rejected expired token")
            print(f"  Error: {e}")
            return TestResult("temporal-tampering", True, str(e))
        print(f"  PASS: Client rejected token: {e}")
        return TestResult("temporal-tampering", True, str(e))


def test_issuer_confusion() -> TestResult:
    """Test 4: Issuer Confusion Attack."""
    print("\nTest 4: Issuer Confusion Attack")
    print("-" * 40)

    session_id = create_session("python-issuer-test", ["issuer-confusion"])
    if not session_id:
        return TestResult("issuer-confusion", False, "Could not create session")

    token = get_token(session_id)
    if not token:
        return TestResult("issuer-confusion", False, "Could not get token")

    try:
        validate_token(token)
        print("  FAIL: Client accepted token with wrong issuer!")
        return TestResult("issuer-confusion", False, "Client accepted wrong issuer")
    except ValueError as e:
        if "issuer" in str(e).lower():
            print(f"  PASS: Client correctly rejected wrong issuer")
            print(f"  Error: {e}")
            return TestResult("issuer-confusion", True, str(e))
        print(f"  PASS: Client rejected token: {e}")
        return TestResult("issuer-confusion", True, str(e))


def test_valid_token() -> TestResult:
    """Test 5: Valid Token (No Mischief)."""
    print("\nTest 5: Valid Token (No Mischief)")
    print("-" * 40)

    # No session ID = no mischief
    token = get_token()
    if not token:
        return TestResult("valid-token", False, "Could not get token")

    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "unknown")

        if alg in ("RS256", "ES256"):
            print(f"  PASS: Token uses proper algorithm: {alg}")
            return TestResult("valid-token", True, f"Algorithm: {alg}")
        else:
            print(f"  INFO: Token uses algorithm: {alg}")
            return TestResult("valid-token", True, f"Algorithm: {alg}")
    except Exception as e:
        print(f"  FAIL: Could not parse token: {e}")
        return TestResult("valid-token", False, str(e))


def main():
    print("=" * 50)
    print("OIDC-Loki Python Client Security Tests")
    print("=" * 50)

    results = [
        test_alg_none(),
        test_key_confusion(),
        test_temporal_tampering(),
        test_issuer_confusion(),
        test_valid_token(),
    ]

    # Summary
    print("\n" + "=" * 50)
    print("Summary")
    print("=" * 50)
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    print(f"Passed: {passed}/{total}")

    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"  [{status}] {result.name}: {result.message}")

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
