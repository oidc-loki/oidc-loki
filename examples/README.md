# OIDC-Loki Client Examples

Example clients demonstrating how to test OIDC client implementations against OIDC-Loki's malicious tokens.

## Prerequisites

1. Start OIDC-Loki server:
   ```bash
   # From the oidc-loki root directory
   npm run dev
   ```

   The server will start on `http://localhost:9000` by default.

2. Ensure a test client is configured. The examples expect:
   - Client ID: `test-client`
   - Client Secret: `test-secret`
   - Grant Type: `client_credentials`

## Examples

### Go

```bash
cd examples/go
go mod download
go run main.go
```

**Dependencies:** `github.com/golang-jwt/jwt/v5`

### Python

```bash
cd examples/python
pip install -r requirements.txt
python test_oidc_security.py
```

**Dependencies:** `PyJWT`, `requests`

### Rust

```bash
cd examples/rust
cargo run
```

**Dependencies:** `jsonwebtoken`, `reqwest`, `serde`, `base64`

### Java

```bash
cd examples/java
./gradlew run
# Or with Maven: mvn exec:java
```

**Dependencies:** `jackson-databind` (uses java.net.http.HttpClient from JDK 11+)

## What the Examples Test

Each example runs the same security tests:

| Test | Attack | What It Validates |
|------|--------|-------------------|
| **alg-none** | Removes JWT signature | Client rejects unsigned tokens |
| **key-confusion** | RS256→HS256 with public key | Client rejects symmetric algorithms |
| **temporal-tampering** | Expired timestamps | Client validates token expiration |
| **issuer-confusion** | Spoofed issuer claim | Client validates issuer |
| **valid-token** | No mischief applied | Client accepts valid tokens |

## How It Works

1. **Create Session**: The client creates a "mischief session" via the Admin API
   ```
   POST /admin/sessions
   {"name": "test", "mode": "explicit", "mischief": ["alg-none"]}
   ```

2. **Get Token**: Request a token with the session ID header
   ```
   POST /token
   X-Loki-Session: sess_xxx
   Authorization: Basic base64(client:secret)
   ```

3. **Validate**: The client's validation logic should reject malicious tokens

## Expected Output

```
==================================================
OIDC-Loki [Language] Client Security Tests
==================================================

Test 1: Algorithm None Attack
----------------------------------------
  PASS: Client correctly rejected alg:none token
  Error: SECURITY: token uses alg:none - unsigned tokens not allowed

Test 2: Key Confusion Attack
----------------------------------------
  PASS: Client correctly rejected HS256 token
  Error: SECURITY: symmetric algorithm HS256 not allowed...

...

==================================================
Summary
==================================================
Passed: 5/5
  [PASS] alg-none: Client rejected unsigned token
  [PASS] key-confusion: Client rejected HS256 token
  [PASS] temporal-tampering: Client rejected expired token
  [PASS] issuer-confusion: Client rejected wrong issuer
  [PASS] valid-token: Algorithm: RS256
```

## Adapting for Your Client

These examples demonstrate **what** to test, not **how** your production code should work. To test your actual OIDC client:

1. Replace the `validateToken()` function with your client's validation
2. Point the tests at your client library
3. Assert that malicious tokens are rejected

### Example: Testing a Production Client

```python
# Instead of the example validateToken(), use your real client:
from your_oidc_library import OIDCClient

client = OIDCClient(
    issuer=LOKI_URL,
    client_id=CLIENT_ID,
    # ... your config
)

def test_alg_none():
    session_id = create_session("test", ["alg-none"])
    token = get_token(session_id)

    # This should raise an exception
    try:
        client.validate_token(token)
        assert False, "Client accepted alg:none token!"
    except InvalidTokenError:
        pass  # Expected - client correctly rejected
```

## Security Considerations

- These examples intentionally accept/inspect malicious tokens for testing
- **Never** use this validation logic in production
- In production, always:
  - Verify signatures using JWKS
  - Validate all claims (iss, aud, exp, nbf)
  - Use established OIDC libraries
  - Pin to asymmetric algorithms only

## Adding More Languages

PRs welcome! To add a new language example:

1. Create a directory: `examples/<language>/`
2. Implement the same test pattern:
   - `createSession()` - POST to `/admin/sessions`
   - `getToken()` - POST to `/token` with session header
   - `validateToken()` - Security checks (alg, exp, iss)
   - Run tests for each attack type
3. Include dependency file (go.mod, requirements.txt, Cargo.toml, etc.)
4. Update this README
