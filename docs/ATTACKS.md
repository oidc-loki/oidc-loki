# OIDC-Loki Attack Catalog

This document describes all 36 built-in mischief plugins, organized by category. Each plugin tests a specific vulnerability or misconfiguration in OIDC/OAuth implementations.

## Table of Contents

- [Signature/Algorithm Attacks](#signaturealgorithm-attacks)
- [Claims Manipulation Attacks](#claims-manipulation-attacks)
- [Flow/Protocol Attacks](#flowprotocol-attacks)
- [Discovery/JWKS Attacks](#discoveryjwks-attacks)
- [Resilience Testing](#resilience-testing)
- [Attack Profiles](#attack-profiles)

---

## Signature/Algorithm Attacks

### alg-none (Critical)
**Phase:** token-signing
**CWE:** CWE-327
**RFC:** RFC 7518 Section 3.6

Sets the JWT algorithm header to "none" and removes the signature. Tests whether the relying party accepts unsigned tokens.

**What it tests:** Clients must reject tokens with `alg: none` in production. This attack exploits implementations that blindly trust the algorithm specified in the token header.

**Remediation:** Always validate that tokens use an expected algorithm (RS256, ES256, etc.) and reject `none`.

---

### key-confusion (Critical)
**Phase:** token-signing
**CWE:** CWE-327
**RFC:** RFC 7515

Changes RS256 to HS256 and signs with the public key as a symmetric secret. Tests for algorithm confusion vulnerabilities.

**What it tests:** When a client uses the public RSA key (intended for verification) as an HMAC secret, an attacker who knows the public key can forge valid signatures.

**Remediation:** Explicitly specify allowed algorithms when verifying tokens. Never accept HS256 for tokens that should be signed with RS256.

---

### weak-algorithms (Critical)
**Phase:** token-signing
**CWE:** CWE-327
**RFC:** RFC 7518

Signs tokens with deprecated/weak algorithms like RS384, PS256, or HS384 to test algorithm allowlisting.

**What it tests:** Whether clients accept algorithms outside the expected set. Some algorithms may be deprecated or have known weaknesses.

**Remediation:** Maintain a strict allowlist of accepted algorithms and reject all others.

---

### jku-injection (Critical)
**Phase:** token-signing
**CWE:** CWE-345
**RFC:** RFC 7515 Section 4.1.2

Adds a `jku` (JWK Set URL) header pointing to an attacker-controlled URL. Tests if clients fetch keys from untrusted sources.

**What it tests:** If a client fetches signing keys from the URL specified in the token's jku header without validation, an attacker can provide their own keys and forge tokens.

**Remediation:** Never trust the jku header. Always use pre-configured JWKS endpoints.

---

### x5u-injection (Critical)
**Phase:** token-signing
**CWE:** CWE-345
**RFC:** RFC 7515 Section 4.1.5

Adds an `x5u` (X.509 URL) header pointing to an attacker-controlled certificate chain.

**What it tests:** Similar to jku-injection, but uses X.509 certificate URLs instead of JWK Sets.

**Remediation:** Never trust the x5u header. Use pre-configured certificate authorities.

---

### embedded-jwk-attack (Critical)
**Phase:** token-signing
**CWE:** CWE-345
**RFC:** RFC 7515 Section 4.1.3

Embeds a complete JWK in the token header and signs with that key.

**What it tests:** If clients use the embedded key from the `jwk` header to verify the signature, attackers can sign tokens with any key.

**Remediation:** Ignore embedded JWK headers. Only use keys from your configured JWKS endpoint.

---

### curve-confusion (Critical)
**Phase:** token-signing
**CWE:** CWE-327
**RFC:** RFC 7518

Uses weak or mismatched elliptic curves for ECDSA signatures.

**What it tests:** Whether clients properly validate the curve used for ECDSA signatures. Some implementations may be vulnerable to invalid curve attacks.

**Remediation:** Validate that EC keys use expected curves (P-256, P-384, P-521) and reject others.

---

### kid-manipulation (High)
**Phase:** token-signing
**CWE:** CWE-290
**RFC:** RFC 7515 Section 4.1.4

Manipulates the `kid` (Key ID) header to reference different keys or use path traversal patterns.

**What it tests:** Whether clients properly sanitize kid values before using them to look up keys. Malicious kid values might cause path traversal or SQL injection.

**Remediation:** Sanitize kid values and use allowlisted key identifiers only.

---

### token-type-confusion (High)
**Phase:** token-signing
**CWE:** CWE-287
**OIDC:** Core Section 2

Modifies the `typ` header to misrepresent the token type (e.g., changing ID token to access token type).

**What it tests:** Whether clients validate the token type matches what they expect. Accepting an access token where an ID token is expected can lead to security issues.

**Remediation:** Always validate the `typ` header matches expectations for the token context.

---

### crit-header-bypass (High)
**Phase:** token-signing
**CWE:** CWE-287
**RFC:** RFC 7515 Section 4.1.11

Adds a `crit` header with unsupported extensions to test critical header processing.

**What it tests:** RFC 7515 requires that tokens with `crit` headers listing unsupported extensions must be rejected.

**Remediation:** Implement proper crit header validation per RFC 7515.

---

### jwks-domain-mismatch (Critical)
**Phase:** token-signing
**CWE:** CWE-345
**OIDC:** Discovery 1.0

Signs tokens with keys that don't match the issuer's domain.

**What it tests:** Whether clients verify that JWKS keys belong to the expected issuer domain.

**Remediation:** Validate that JWKS endpoints are hosted on the issuer's domain.

---

## Claims Manipulation Attacks

### issuer-confusion (Critical)
**Phase:** token-claims
**CWE:** CWE-290
**RFC:** RFC 7519 Section 4.1.1

Modifies the `iss` claim to impersonate a different identity provider.

**What it tests:** Whether clients properly validate the issuer claim against expected values.

**Remediation:** Validate `iss` against a strict allowlist of trusted issuers.

---

### audience-confusion (Critical)
**Phase:** token-claims
**CWE:** CWE-290
**RFC:** RFC 7519 Section 4.1.3

Modifies the `aud` claim to target different applications or use wildcard patterns.

**What it tests:** Whether clients validate that they are the intended audience for the token.

**Remediation:** Always validate `aud` contains your application's client ID.

---

### subject-manipulation (Critical)
**Phase:** token-claims
**CWE:** CWE-287
**RFC:** RFC 7519 Section 4.1.2

Modifies the `sub` claim to impersonate different users (admin, root, etc.).

**What it tests:** Whether clients blindly trust the subject claim without additional verification.

**Remediation:** Validate subjects against expected patterns and user databases.

---

### scope-injection (Critical)
**Phase:** token-claims
**CWE:** CWE-269
**RFC:** RFC 6749 Section 3.3

Injects elevated scopes like `admin`, `write:all`, or `*` into the token.

**What it tests:** Whether clients validate scopes against what was actually granted.

**Remediation:** Compare token scopes against the scopes that were approved during authorization.

---

### temporal-tampering (High)
**Phase:** token-claims
**CWE:** CWE-613
**RFC:** RFC 7519 Section 4.1.4

Manipulates `iat`, `exp`, and `nbf` claims to create tokens that are already expired, not yet valid, or valid for extremely long periods.

**What it tests:** Whether clients properly validate temporal claims.

**Remediation:** Strictly validate all temporal claims with reasonable clock skew tolerance.

---

### azp-confusion (High)
**Phase:** token-claims
**CWE:** CWE-284
**OIDC:** Core Section 2

Sets the `azp` (authorized party) claim to a different client to test cross-client token acceptance.

**What it tests:** Whether clients validate that they are the authorized party for the token.

**Remediation:** Validate `azp` matches your client ID when present.

---

### at-hash-c-hash-mismatch (High)
**Phase:** token-claims
**CWE:** CWE-347
**OIDC:** Core Section 3.3.2.11

Creates mismatched `at_hash` and `c_hash` values in ID tokens.

**What it tests:** Whether clients validate that hash claims match the actual access token and authorization code.

**Remediation:** Always validate at_hash and c_hash per OIDC Core specification.

---

### token-lifetime-abuse (High)
**Phase:** token-claims
**CWE:** CWE-613
**RFC:** RFC 7519 Section 4.1.4

Issues tokens with excessively long lifetimes (months to years).

**What it tests:** Whether clients enforce maximum token lifetime policies.

**Remediation:** Reject tokens with unreasonably long lifetimes (e.g., > 1 hour for access tokens).

---

### claim-type-coercion (Medium)
**Phase:** token-claims
**CWE:** CWE-704
**RFC:** RFC 7519

Sends claims with unexpected types (string "true" instead of boolean, array instead of string).

**What it tests:** Whether clients handle type coercion safely when processing claims.

**Remediation:** Strictly validate claim types before processing.

---

### unicode-normalization (Medium)
**Phase:** token-claims
**CWE:** CWE-176
**RFC:** RFC 7519

Injects Unicode lookalikes, zero-width characters, and normalization edge cases into claims.

**What it tests:** Whether clients normalize Unicode before string comparison.

**Remediation:** Normalize Unicode strings (NFC or NFKC) before comparing claim values.

---

### json-parsing-differentials (Medium)
**Phase:** token-claims
**CWE:** CWE-436
**RFC:** RFC 8259

Exploits JSON parsing differences (duplicate keys, trailing commas, special numbers).

**What it tests:** Whether different JSON parsers in the pipeline interpret tokens consistently.

**Remediation:** Use a strict JSON parser and validate parsed values.

---

## Flow/Protocol Attacks

### nonce-bypass (High)
**Phase:** response
**CWE:** CWE-352
**OIDC:** Core Section 3.1.2.1

Removes or manipulates the `nonce` claim to test CSRF protections.

**What it tests:** Whether clients validate the nonce matches what was sent in the authorization request.

**Remediation:** Always validate nonce for implicit and hybrid flows.

---

### state-bypass (High)
**Phase:** response
**CWE:** CWE-352
**RFC:** RFC 6749 Section 10.12

Removes or manipulates the `state` parameter in authorization responses.

**What it tests:** Whether clients validate state for CSRF protection.

**Remediation:** Always validate state parameter matches what was sent.

---

### pkce-downgrade (High)
**Phase:** response
**CWE:** CWE-287
**RFC:** RFC 7636

Allows authorization without code_verifier when PKCE was initiated.

**What it tests:** Whether clients enforce PKCE when it was used during authorization.

**Remediation:** Require code_verifier for all exchanges when code_challenge was provided.

---

### response-mode-mismatch (Medium)
**Phase:** response
**CWE:** CWE-287
**OIDC:** Core Section 3

Returns tokens using a different response_mode than requested.

**What it tests:** Whether clients validate the response mode matches what was requested.

**Remediation:** Validate response mode and reject mismatches.

---

### iss-in-response-attack (Critical)
**Phase:** response
**CWE:** CWE-290
**RFC:** RFC 9207

Omits or modifies the `iss` parameter in authorization responses (mix-up attack vector).

**What it tests:** Defense against IdP mix-up attacks where an attacker's IdP can steal authorization codes.

**Remediation:** Always require and validate the `iss` parameter in authorization responses.

---

### response-type-confusion (High)
**Phase:** token-claims
**CWE:** CWE-287
**OIDC:** Core Section 3

Adds unexpected claims that shouldn't be present for the requested response type.

**What it tests:** Whether clients reject tokens with unexpected parameters for the flow type.

**Remediation:** Validate that only expected parameters are present for the response type.

---

## Discovery/JWKS Attacks

### discovery-confusion (Critical)
**Phase:** discovery
**CWE:** CWE-295
**OIDC:** Discovery 1.0

Serves malicious `.well-known/openid-configuration` with poisoned endpoints.

**What it tests:** Whether clients properly validate discovery document contents and endpoint URLs.

**Remediation:** Validate that all endpoints in discovery documents are on expected domains.

---

### jwks-injection (Critical)
**Phase:** discovery
**CWE:** CWE-295
**RFC:** RFC 7517

Serves JWKS with attacker-controlled keys injected alongside legitimate keys.

**What it tests:** Whether clients validate key sources and only accept expected keys.

**Remediation:** Pin expected keys or validate key properties strictly.

---

### massive-jwks (Medium)
**Phase:** discovery
**CWE:** CWE-400
**RFC:** RFC 7517

Returns a JWKS with thousands of keys to test DoS resilience.

**What it tests:** Whether clients handle large JWKS responses without performance degradation.

**Remediation:** Limit the number of keys processed and use timeouts.

---

### massive-metadata (Medium)
**Phase:** discovery
**CWE:** CWE-400
**OIDC:** Discovery 1.0

Returns discovery metadata with oversized arrays and deeply nested structures.

**What it tests:** Whether clients handle malformed/oversized discovery documents safely.

**Remediation:** Validate discovery document structure and size limits.

---

## Resilience Testing

### latency-injection (Medium)
**Phase:** response
**CWE:** CWE-400

Adds configurable delays to responses (500ms to 30s).

**What it tests:** Whether clients handle slow identity provider responses gracefully.

**Remediation:** Implement timeouts and circuit breakers for IdP communication.

---

### massive-token (Medium)
**Phase:** token-claims
**CWE:** CWE-400
**RFC:** RFC 7519

Generates tokens with hundreds of claims and large payloads.

**What it tests:** Whether clients handle oversized tokens without memory issues.

**Remediation:** Enforce maximum token size limits before parsing.

---

### error-injection (Medium)
**Phase:** response
**CWE:** CWE-209
**RFC:** RFC 6749 Section 4.1.2.1

Returns various OAuth error responses to test error handling.

**What it tests:** Whether clients handle error responses securely without leaking information.

**Remediation:** Handle all error codes gracefully and avoid exposing internal details.

---

### partial-success (Medium)
**Phase:** response
**CWE:** CWE-754
**RFC:** RFC 6749

Returns incomplete responses (missing token_type, partial JSON).

**What it tests:** Whether clients validate response completeness before processing.

**Remediation:** Validate all required fields are present in responses.

---

## Attack Profiles

OIDC-Loki provides pre-configured attack profiles for common testing scenarios:

| Profile | Description | Plugin Count |
|---------|-------------|--------------|
| `full-scan` | All available plugins | 36 |
| `critical-only` | Only critical severity plugins | 15 |
| `token-validation` | Signature and algorithm attacks | 10 |
| `discovery-attacks` | Discovery and JWKS attacks | 5 |
| `flow-attacks` | OAuth flow manipulation | 6 |
| `resilience` | DoS and stability testing | 6 |
| `parsing-attacks` | Data parsing edge cases | 3 |

### Usage

```typescript
import { Loki } from "oidc-loki";

const loki = new Loki({ /* config */ });
await loki.start();

// Use a profile for session creation
const session = loki.createSession({
  mode: "shuffled",
  mischief: loki.plugins.getProfile("critical-only"),
});
```

---

## References

- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification](https://tools.ietf.org/html/rfc9207)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
