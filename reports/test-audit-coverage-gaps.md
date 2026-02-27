# splice-check Test Suite: Coverage Gap Audit

**Date:** 2026-02-27
**Auditor:** Claude Opus 4.6 (Security Audit)
**Scope:** Identify all missing attack scenarios in the splice-check test suite
**Current test count:** 13 (1 baseline + 12 attack vectors)

---

## Methodology

This audit cross-references the following sources to identify coverage gaps:

1. All 13 existing test implementations in `tools/splice-check/src/tests/`
2. The Gemini adversarial review (`reports/research/gemini-splice-check-review.md`)
3. The consolidated threat catalog (`reports/research/consolidated-threat-catalog.md`)
4. RFC 8693 Sections 1.1, 2.1, 2.2, 4.1, 4.4, and 5 (Security Considerations)
5. RFC 9700 (OAuth 2.0 Security Best Current Practice)
6. CVE-2022-1245 (Keycloak token exchange privilege escalation)
7. CVE-2025-55241 (Microsoft Entra ID actor token vulnerability)
8. IETF OAuth WG delegation chain splicing disclosure

---

## Current Coverage Summary

| Test ID | Name | Threat Category |
|---------|------|-----------------|
| valid-delegation | Valid Delegation (baseline) | Baseline |
| basic-splice | Basic Chain Splice | Chain splicing |
| actor-client-mismatch | Actor-Client Identity Mismatch | Actor impersonation |
| aud-sub-binding | Audience-Subject Binding | Chain validation |
| upstream-splice | Upstream Delegation Splice | Re-delegation |
| subject-actor-swap | Subject-Actor Token Swap | Role inversion |
| multi-audience | Multi-Audience Subject Token | Permissive matching |
| missing-aud | Missing Audience Claim | Missing validation input |
| may-act-enforcement | may_act Enforcement | Authorization policy |
| scope-escalation | Scope Escalation Through Exchange | Privilege escalation |
| delegation-impersonation-confusion | Delegation vs Impersonation Confusion | Semantic confusion |
| refresh-bypass | Refresh Token Bypass | Persistence |
| revocation-propagation | Revocation Propagation | Revocation |

**What is well-covered:** Core chain splicing, actor identity validation, aud/sub binding, subject-actor role confusion, scope escalation, delegation vs impersonation semantics, revocation lifecycle.

**What is absent:** Token type confusion, cross-issuer exchange, unauthenticated exchange, target audience manipulation, chain depth enforcement, expired token handling, replay attacks, `act` claim integrity in output tokens, `resource` parameter abuse, `requested_token_type` escalation, and several timing/operational attacks.

---

## Identified Gaps

### 1. MUST-HAVE -- Critical gaps that undermine the tool's credibility

These gaps represent fundamental attack classes that any RFC 8693 conformance tool must cover. Their absence means an AS could pass all 13 tests while remaining exploitable.

---

#### TE-01: Token Type Indicator Mismatch

**Severity:** Critical
**RFC Reference:** RFC 8693 Section 2.1 -- "The authorization server MUST perform the appropriate validation procedures for the indicated token type"
**Threat Catalog Reference:** Gemini review 3.4, Plugin inventory #16 (`token-type-indicator-mismatch`)

**Description:** An attacker presents an access_token but declares it as `subject_token_type: urn:ietf:params:oauth:token-type:id_token` (or vice versa). If the AS blindly trusts the type indicator without validating the actual token content against the declared type, it may apply the wrong validation rules -- for example, skipping audience validation that applies to access tokens, or treating an id_token as an access credential.

**Setup:**
1. Obtain Alice's access_token via client_credentials
2. Obtain Agent A's access_token

**Attack:**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<alice_access_token>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token  // LIE
&actor_token=<agent_a_token>
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
```

**Verify:** AS should reject with `invalid_request` because the token content does not match the declared type. If the AS accepts, it means type indicators are not validated.

**Why it matters:** This is a precondition for many downstream attacks. If the AS ignores type indicators, an attacker can feed refresh_tokens as subject_tokens, id_tokens as actor_tokens, etc. CVE-2022-1245 (Keycloak) demonstrated that insufficient input validation in token exchange leads to CVSS 9.8 severity. Token type confusion is the simplest possible validation bypass and is explicitly called out in the RFC as a MUST.

---

#### TE-02: Unauthenticated Token Exchange

**Severity:** Critical
**RFC Reference:** RFC 8693 Section 5 -- "Omitting client authentication allows for a compromised token to be leveraged via an STS into other tokens by anyone possessing the compromised token"
**Threat Catalog Reference:** Plugin inventory #18 (`unauthenticated-exchange`)

**Description:** An attacker sends a token exchange request with no client authentication at all (no client_id, no client_secret, no Authorization header). If the AS processes the exchange without verifying who the requesting client is, any party with a stolen token can mint new tokens.

**Setup:**
1. Obtain Alice's access_token via legitimate means

**Attack:**
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<alice_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
// NO client_id, NO client_secret, NO Authorization header
```

**Verify:** AS should reject with `invalid_client` (HTTP 401). If it returns 200 with an access_token, client authentication is not enforced for token exchange.

**Why it matters:** RFC 8693 Section 5 explicitly warns about this. Without client authentication, token exchange becomes a universal token laundering endpoint. A leaked access_token becomes a skeleton key. This is the single most basic security check and its absence makes all other tests meaningless.

**Implementation note:** This test requires the client module to support sending requests without authentication. The `OAuthClient` currently always applies client auth via `applyClientAuth()`. A raw HTTP request or a bypass flag would be needed.

---

#### TE-03: Requested Token Type Escalation

**Severity:** Critical
**RFC Reference:** RFC 8693 Section 2.1 (`requested_token_type` parameter)
**Threat Catalog Reference:** Related to CD-02, DI-02

**Description:** An attacker uses `requested_token_type` to request a more privileged token type than appropriate. Specifically:
- Exchange an access_token and request `urn:ietf:params:oauth:token-type:refresh_token` -- obtaining a long-lived refresh token from a short-lived access token
- Exchange an access_token and request `urn:ietf:params:oauth:token-type:id_token` -- obtaining an identity assertion that may be accepted elsewhere

**Setup:**
1. Obtain Alice's access_token via client_credentials

**Attack (variant A -- refresh_token escalation):**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<alice_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&requested_token_type=urn:ietf:params:oauth:token-type:refresh_token
```

**Attack (variant B -- id_token extraction):**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<alice_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&requested_token_type=urn:ietf:params:oauth:token-type:id_token
```

**Verify:** AS should reject the escalation (especially access_token to refresh_token) or at minimum constrain the issued token's lifetime and scope. Accepting these exchanges silently converts temporary access into persistent access.

**Why it matters:** This is analogous to CVE-2022-1245 where Keycloak allowed exchanging tokens for arbitrary target clients. An AS that honors any `requested_token_type` without policy checks enables token type privilege escalation. An access token should never be convertible into a refresh token via exchange -- this bypasses the user's consent flow entirely.

---

#### TE-04: Audience Targeting to Unauthorized Resource

**Severity:** Critical
**RFC Reference:** RFC 8693 Section 2.1 (`audience` parameter), Section 2.2.1 (`invalid_target` error code)
**Threat Catalog Reference:** CD-04, Keycloak CVE-2022-1245

**Description:** An attacker provides an `audience` parameter pointing to a different client/resource that the requesting client should not be able to target. This directly mirrors CVE-2022-1245 where Keycloak allowed exchanging tokens for any target client by passing the client_id of the target.

**Setup:**
1. Obtain Alice's access_token
2. Identify a high-privilege client_id (e.g., "admin-service") that agent-n should not be able to target

**Attack:**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<alice_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=admin-service  // Unauthorized target
&client_id=agent-n
&client_secret=...
```

**Verify:** AS should reject with `invalid_target`. The requesting client must be authorized to exchange tokens targeting the specified audience. If the AS issues a token scoped to an arbitrary audience, it means any client can mint tokens for any service.

**Why it matters:** This is a real-world vulnerability class (CVE-2022-1245, CVSS 9.8). The existing `aud-sub-binding` test validates aud/sub matching for splice prevention, but does not test whether the AS restricts which audiences a client is authorized to target. These are complementary but distinct checks.

---

#### TE-05: `act` Claim Stripping / Delegation-to-Impersonation Downgrade

**Severity:** Critical
**RFC Reference:** RFC 8693 Section 1.1, Section 4.1
**Threat Catalog Reference:** ACT-06, DI-01, DI-03

**Description:** An attacker takes a delegation token (containing `act` claim) from a prior exchange and feeds it back into token exchange *without* an `actor_token`. If the AS strips the `act` claim and issues a plain impersonation token, the delegation audit trail is destroyed. The resulting token appears to be the subject acting directly, with no record that delegation occurred.

This is distinct from `delegation-impersonation-confusion` (which tests that delegation *produces* an `act` claim). This test verifies that existing `act` claims survive re-exchange.

**Setup:**
1. Obtain Alice's token
2. Exchange Alice's token with Agent A's actor_token to get a delegation token with `act` claim
3. Verify the delegation token contains `act`

**Attack:**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<delegation_token_with_act>  // Has act claim
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
// NO actor_token -- requesting impersonation of a delegation token
```

**Verify:**
- If the AS rejects: PASS (correctly refuses to strip delegation context)
- If the AS returns a token without `act`: FAIL (audit trail destroyed)
- If the AS returns a token preserving or extending `act`: PASS

**Why it matters:** CVE-2025-55241 (Microsoft Entra ID) proved that `act` claim manipulation leads to Critical-severity cross-tenant impersonation. Stripping `act` is the simplest form of this attack. In agentic AI systems, the delegation audit trail is the only mechanism for answering "who authorized this action?" Destroying it enables unattributable actions.

---

### 2. SHOULD-HAVE -- Important scenarios for comprehensive coverage

These represent significant attack classes that a thorough compliance tool should cover to claim comprehensive RFC 8693 security testing.

---

#### TE-06: Expired Subject Token Acceptance

**Severity:** High
**RFC Reference:** RFC 8693 Section 2.1 -- "MUST perform the appropriate validation procedures for the indicated token type"
**Threat Catalog Reference:** Gemini review 3.6

**Description:** An attacker presents an expired `subject_token` in the exchange. A correctly implementing AS should validate token expiry as part of "appropriate validation procedures." A misconfigured AS that only validates the grant parameters (client auth, grant_type) but not the token itself would accept expired tokens, allowing indefinite reuse of time-limited credentials.

**Setup:**
1. Obtain Alice's access_token
2. Wait for it to expire (or use a very short-lived token if configurable)
3. Record the token for replay

**Attack:**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<expired_alice_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
```

**Verify:** AS should reject with `invalid_grant` or `invalid_request`. If the AS issues a new token, expiry is not validated during exchange.

**Why it matters:** If expired tokens are accepted for exchange, then revoking a user's session does not prevent token re-use via exchange. An attacker who captured a token at any point in its history can exchange it indefinitely. This undermines the entire token lifecycle model.

**Implementation note:** This test is challenging because it requires waiting for token expiry. The test should support configurable delay or allow the operator to provide a pre-expired token. If the token's `exp` claim is far in the future, the test should skip with a clear message.

---

#### TE-07: Expired Actor Token Acceptance

**Severity:** High
**RFC Reference:** RFC 8693 Section 2.1 -- same MUST as TE-06, applied to actor_token
**Threat Catalog Reference:** Extension of Gemini review 3.6

**Description:** Same as TE-06 but for the `actor_token`. If the AS validates the subject_token's expiry but not the actor_token's, a stolen and expired agent credential can still be used for delegation attacks.

**Setup/Attack/Verify:** Mirror TE-06 but with an expired actor_token and a fresh subject_token.

**Why it matters:** Actor tokens represent the agent's *current* authorization to act. An expired actor token means the agent's authorization has lapsed. Accepting it means revoked agents can still act.

---

#### TE-08: Circular Delegation Chain

**Severity:** High
**RFC Reference:** RFC 8693 Section 4.1 (nested `act` claims)
**Threat Catalog Reference:** CD-07, NOVEL-05

**Description:** Can Agent A delegate to Agent B, which then re-delegates back to Agent A? This creates a circular delegation chain: A -> B -> A. Without cycle detection, this can cause:
- Infinite validator loops (DoS)
- Unbounded chain growth
- Confused authorization decisions

**Setup:**
1. Obtain Alice's token
2. Exchange Alice -> Agent A (get delegated token T1)
3. Exchange T1 -> Agent B (get delegated token T2, chain: Alice -> A -> B)

**Attack:**
```
POST /token  (authenticated as Agent A)
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<T2>  // Chain: Alice -> A -> B
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=<agent_a_token>
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
// Result would be: Alice -> A -> B -> A  (circular!)
```

**Verify:** AS should reject the circular delegation. If it accepts, check the resulting token for circular `act` claims.

**Why it matters:** Circular delegation chains have no legitimate use case. Their presence indicates the AS has no cycle detection, which means it is also unlikely to enforce chain depth limits. In agentic AI workloads, agents may legitimately call each other, making accidental circular delegation a realistic scenario -- not just an adversarial one.

**Implementation note:** This requires a fourth client (agent-b) in the config, or reuse of agent-a in both positions. The existing config structure supports adding clients.

---

#### TE-09: Delegation Chain Depth Exhaustion

**Severity:** High
**RFC Reference:** RFC 8693 Section 4.1 (nested `act` claims)
**Threat Catalog Reference:** ACT-04, CD-01

**Description:** An attacker iteratively chains delegation exchanges to create deeply nested `act` claims. Without a maximum depth policy, this leads to:
- Token bloat (each hop adds an `act` layer to the JWT)
- Parser confusion or crashes in resource servers
- Potential DoS via large token sizes

**Setup:**
1. Obtain Alice's token
2. Perform N successive exchanges, each adding a delegation layer

**Attack:** Perform 5-10 successive token exchanges:
```
Alice -> Agent A -> Agent N -> Agent A -> Agent N -> ...
```

**Verify:**
- If the AS rejects at some depth: PASS (chain depth enforced)
- If tokens keep growing indefinitely: FAIL (no depth limit)
- Decode the final token and count nested `act` levels

**Why it matters:** The threat catalog rates this as Medium (downgraded from Critical by Gemini), but in agentic AI systems where multi-hop delegation is common, depth enforcement is a practical necessity. An unbounded chain can also be used to craft tokens that exceed size limits at resource servers, causing availability issues.

---

#### TE-10: Issuer Validation on Subject Token

**Severity:** High
**RFC Reference:** RFC 8693 Section 5, RFC 9700 (issuer validation)
**Threat Catalog Reference:** ACT-03, Gemini review 3.7, 8-Point Mitigation Profile #7

**Description:** The AS should validate that the `subject_token` was issued by a trusted issuer. If an attacker can supply a validly-signed JWT from a different (untrusted) issuer, and the AS accepts it because it doesn't check `iss`, the entire trust model breaks.

**Setup:**
1. Obtain a token from the target AS (to verify baseline works)
2. Craft or obtain a JWT signed by a different issuer (e.g., self-signed JWT with `iss: https://evil.example.com`)

**Attack:**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<foreign_issuer_jwt>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
```

**Verify:** AS should reject with `invalid_grant` because the issuer is not trusted. If it accepts a foreign token, issuer validation is broken.

**Why it matters:** In federated deployments, multiple issuers may exist. An AS that doesn't validate the issuer of incoming tokens will accept tokens minted by any party that can produce a validly-structured JWT. This is the OAuth equivalent of accepting any SSL certificate regardless of CA.

**Implementation note:** This requires the ability to create or import a self-signed JWT. The tool would need a minimal JWT creation capability or accept a pre-crafted token via config.

---

#### TE-11: Resource Parameter Abuse

**Severity:** High
**RFC Reference:** RFC 8693 Section 2.1 (`resource` parameter -- "URI of the target service where the token is intended to be used")
**Threat Catalog Reference:** Gemini review 1.1

**Description:** RFC 8693 defines `resource` as a distinct parameter from `audience`. Some AS implementations use `resource` for audience scoping. An attacker may:
- Provide a `resource` pointing to an internal service URI
- Provide conflicting `resource` and `audience` values
- Provide multiple `resource` values to broaden the token's applicability

**Setup:**
1. Obtain Alice's access_token

**Attack (variant A -- internal resource targeting):**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<alice_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&resource=https://internal-admin-api.corp.example.com
```

**Attack (variant B -- resource/audience conflict):**
```
POST /token
...
&resource=https://service-a.example.com
&audience=service-b  // Conflicting
```

**Verify:** AS should validate that the client is authorized for the specified resource, reject conflicting resource/audience pairs, and not issue tokens for internal-only URIs based on external requests.

**Why it matters:** The `resource` parameter is often overlooked in implementations that primarily use `audience`. An AS that ignores `resource` or treats it permissively allows an attacker to specify where the resulting token should be accepted, potentially gaining access to services the client was never authorized for.

---

#### TE-12: Downstream Token `aud` Verification

**Severity:** High
**RFC Reference:** RFC 8693 Section 2.1, 8-Point Mitigation Profile #4
**Threat Catalog Reference:** Gemini review 4.3

**Description:** After a successful delegation exchange, the resulting token's `aud` claim should be set to the intended downstream actor (or constrained audience). If the AS issues tokens with overly broad or missing `aud`, those tokens can be replayed to any resource server. This is not about *rejecting* an attack -- it's about verifying the AS *produces correctly scoped tokens*.

**Setup:**
1. Obtain Alice's token
2. Perform a legitimate delegation exchange with Agent A, specifying an `audience`

**Attack:** (This is a positive verification test, not an attack per se)
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<alice_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=agent-a-service
```

**Verify:**
1. Exchange succeeds (HTTP 200)
2. Decode the resulting JWT
3. Verify `aud` is set and constrained (not wildcard, not same as original)
4. FAIL if `aud` is missing or overly broad

**Why it matters:** The 8-point mitigation profile requires the AS to set the new token's `aud` to the intended downstream consumer. Without this, delegation tokens are bearer tokens usable anywhere -- defeating the purpose of audience-scoped delegation.

---

#### TE-13: Token Lifetime Reduction Verification

**Severity:** Medium
**RFC Reference:** RFC 8693 Section 2.2 (`expires_in`), RFC 9700 (short token lifetimes)
**Threat Catalog Reference:** Gemini review 4.4, 8-Point Mitigation Profile #5

**Description:** Delegated tokens should have equal or shorter lifetimes than the original subject_token. If a delegation exchange extends the token's lifetime, it undermines time-based access control. An attacker could use delegation exchange as a token refresh mechanism.

**Setup:**
1. Obtain Alice's token, record its `exp` claim
2. Perform a delegation exchange with Agent A

**Verify:**
1. Decode the resulting token
2. Compare `exp` of the result with `exp` of the original
3. FAIL if the delegated token expires *after* the original
4. PASS if the delegated token has equal or shorter lifetime

**Why it matters:** RFC 9700 recommends short token lifetimes. If token exchange can extend lifetimes, it becomes a persistence mechanism. An attacker with a token about to expire can exchange it for a fresh long-lived one.

---

#### TE-14: `issued_token_type` Response Validation

**Severity:** Medium
**RFC Reference:** RFC 8693 Section 2.2.1 -- `issued_token_type` is REQUIRED in the response
**Threat Catalog Reference:** Gemini review 1.4

**Description:** The `issued_token_type` response field tells the client what type of token was actually issued. If the AS omits it, the client cannot verify that it received the expected token type. If the AS returns a different type than requested, the client may misuse the token.

**Setup/Attack:** Perform a successful baseline delegation exchange.

**Verify:**
1. Response includes `issued_token_type` (REQUIRED per spec)
2. The value matches one of the defined token type URIs
3. If `requested_token_type` was specified, verify `issued_token_type` is consistent

**Why it matters:** Compliance test. An AS that omits `issued_token_type` is violating a MUST-level requirement. Clients relying on this field for token handling may misinterpret the token.

---

#### TE-15: `act.sub` Matches Intended Actor (Output Validation)

**Severity:** High
**RFC Reference:** RFC 8693 Section 4.1
**Threat Catalog Reference:** ACT-07

**Description:** After a successful delegation exchange, verify that the `act.sub` claim in the resulting token actually matches the actor that was specified. An AS with buggy claim construction might set `act.sub` to the wrong value (e.g., the subject's identity, a previous actor, or a default value).

**Setup:**
1. Obtain Alice's token and Agent A's token
2. Perform delegation exchange as Agent A

**Verify:**
1. Decode the resulting JWT
2. Verify `act.sub` matches Agent A's identity (not Alice's, not another agent)
3. FAIL if `act.sub` is wrong or missing

**Why it matters:** Even if the AS correctly validates inputs, a bug in output token construction could assign the wrong actor identity. Resource servers relying on `act.sub` for authorization would then apply the wrong policy. This tests the output rather than just the input validation.

---

#### TE-16: `act` Claim Nesting Integrity

**Severity:** High
**RFC Reference:** RFC 8693 Section 4.1 -- "A chain of delegation can be expressed by nesting one act claim within another"
**Threat Catalog Reference:** ACT-02, ACT-05, ACT-08

**Description:** After a multi-hop delegation (Alice -> Agent A -> Agent B), verify that the resulting token's `act` chain correctly reflects the delegation history. Specifically:
- The outermost `act` should identify the current actor (Agent B)
- The nested `act` within it should identify the prior actor (Agent A)
- No claims from the subject (Alice) should appear in `act` inappropriately
- Non-identity claims (`exp`, `nbf`, `aud`) should NOT appear inside `act` objects

**Setup:**
1. Obtain Alice's token
2. Exchange Alice -> Agent A (T1 with `act.sub = agent-a`)
3. Exchange T1 -> Agent B (T2 should have nested act)

**Verify:**
1. Decode T2 and inspect the `act` chain
2. Verify `act.sub` = agent-b (current actor)
3. Verify `act.act.sub` = agent-a (prior actor)
4. Verify no non-identity claims inside `act` objects

**Why it matters:** Improper `act` construction (ACT-08) or non-identity claim leakage (ACT-05) can confuse resource server validators. If the delegation chain history is incorrect, audit trails become unreliable.

---

### 3. NICE-TO-HAVE -- Edge cases that round out the suite

These tests cover less common scenarios but address real attack surfaces identified in the threat research.

---

#### TE-17: Same Token as Both Subject and Actor

**Severity:** Medium
**RFC Reference:** RFC 8693 Section 2.1
**Threat Catalog Reference:** None -- novel edge case

**Description:** An attacker presents the same token as both `subject_token` and `actor_token`. This is a degenerate case that should be rejected since an entity cannot delegate to itself within the same exchange.

**Setup:**
1. Obtain Agent N's token

**Attack:**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<agent_n_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=<agent_n_token>  // Same token!
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
```

**Verify:** AS should reject. Accepting means no deduplication check on input tokens.

**Why it matters:** While unlikely to be exploited directly, this tests a boundary condition in the AS's input validation. An AS that accepts this reveals it performs no cross-validation between the two token parameters at all.

---

#### TE-18: Exchange Without `actor_token_type` When `actor_token` Is Present

**Severity:** Medium
**RFC Reference:** RFC 8693 Section 2.1 -- "actor_token_type: REQUIRED when the actor_token element is present"

**Description:** RFC 8693 says `actor_token_type` is REQUIRED when `actor_token` is provided. An attacker omits `actor_token_type` while including `actor_token` to see if the AS infers or ignores the type.

**Setup:**
1. Obtain Alice's token and Agent A's token

**Attack:**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<alice_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=<agent_a_token>
// actor_token_type OMITTED (violation)
```

**Verify:** AS should reject with `invalid_request`. If the AS accepts, it means required parameters are not enforced.

**Why it matters:** Compliance test. Lenient parameter validation in security-critical endpoints is a code smell that suggests other validation is also lenient.

---

#### TE-19: Exchange with `subject_token_type` as `refresh_token`

**Severity:** Medium
**RFC Reference:** RFC 8693 Section 2.1, Section 3 (token type identifiers)

**Description:** An attacker presents a refresh_token as the `subject_token` with the correct type indicator `urn:ietf:params:oauth:token-type:refresh_token`. The AS should have policy about whether refresh tokens can be used as subject tokens in exchanges -- most should reject this since refresh tokens are meant for the token endpoint's refresh_token grant, not for exchange.

**Setup:**
1. Obtain a refresh_token (via delegation exchange with `offline_access` scope)

**Attack:**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<refresh_token>
&subject_token_type=urn:ietf:params:oauth:token-type:refresh_token
```

**Verify:** AS should reject. A refresh_token represents an ongoing authorization grant, not a security identity that should be delegated. If accepted, the exchange effectively transforms a single-use credential into a bearer credential.

**Why it matters:** Refresh tokens are high-value credentials with different security properties than access tokens. Allowing them as exchange inputs creates a novel token laundering vector.

---

#### TE-20: `actor_token` Without `subject_token` (Malformed Request)

**Severity:** Low
**RFC Reference:** RFC 8693 Section 2.1 -- `subject_token` and `subject_token_type` are REQUIRED

**Description:** A malformed request that includes `actor_token` but omits `subject_token`. This is a basic input validation check.

**Setup:** Obtain any token.

**Attack:**
```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&actor_token=<some_token>
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
// subject_token OMITTED
```

**Verify:** AS should reject with `invalid_request`.

**Why it matters:** Basic robustness test. An AS that processes exchanges without a subject token has a fundamental parsing bug.

---

#### TE-21: Replay of Previously Exchanged Token

**Severity:** Medium
**RFC Reference:** RFC 8693 Section 2.1 -- "the act of performing a token exchange has no impact on the validity of the subject token"
**Threat Catalog Reference:** CS-03 (TOCTOU)

**Description:** After a successful exchange, replay the same `subject_token` in a new exchange request. RFC 8693 explicitly says exchange does not invalidate the input tokens unless the token type specifies one-time-use semantics. However, an AS could optionally implement replay detection for delegation tokens to prevent the same token from being used to create multiple independent delegation chains.

**Setup:**
1. Obtain Alice's token
2. Perform Exchange #1: Alice -> Agent A (succeeds)

**Attack:**
```
// Exchange #2: Same Alice token -> Agent N
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<same_alice_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=<agent_n_token>
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
```

**Verify:** This is informational rather than pass/fail. The key observation is whether the AS:
- Allows multiple independent delegations from the same token (RFC-compliant but risky)
- Detects and limits concurrent delegation chains (defense-in-depth)

**Why it matters:** If the same subject_token can be exchanged multiple times with different actors, a single stolen token creates multiple independent delegation chains. This amplifies the impact of token theft.

---

#### TE-22: Token Exchange as Non-Exchange Grant Type

**Severity:** Low
**RFC Reference:** RFC 8693 Section 2.1 (grant_type)

**Description:** Send the token exchange parameters but with a different `grant_type` (e.g., `authorization_code` or `client_credentials`). This tests whether the AS only processes exchange logic when the correct grant type is specified.

**Setup:** Obtain Alice's token.

**Attack:**
```
POST /token
grant_type=client_credentials
&subject_token=<alice_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
```

**Verify:** AS should either ignore the exchange-specific parameters (process as normal client_credentials) or reject the request. It should NOT process it as a token exchange.

**Why it matters:** Parameter pollution test. Ensures the AS's grant type routing is clean.

---

#### TE-23: Exchange with Empty/Malformed Token Values

**Severity:** Low
**RFC Reference:** RFC 8693 Section 2.1

**Description:** Send exchange requests with pathological token values:
- Empty string as `subject_token`
- Extremely long random string (>64KB)
- Non-UTF8 binary data
- SQL injection payload
- JWT with `alg: none`

**Setup:** None required (no real tokens needed).

**Attack:** Multiple variants testing input robustness.

**Verify:** AS should reject all variants with appropriate error codes, not crash or leak information.

**Why it matters:** Robustness and fuzzing. An AS that crashes on malformed input has a denial-of-service vulnerability. Information leakage in error responses can aid further attacks.

---

#### TE-24: Impersonation Without Explicit Authorization

**Severity:** Medium
**RFC Reference:** RFC 8693 Section 1.1, Section 5
**Threat Catalog Reference:** DI-02

**Description:** Perform a token exchange *without* an `actor_token` (requesting impersonation semantics). The AS should either reject impersonation entirely or require explicit authorization for the requesting client to impersonate the subject.

**Setup:**
1. Obtain Alice's token

**Attack:**
```
POST /token  (authenticated as Agent N)
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<alice_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
// NO actor_token -- requesting impersonation
```

**Verify:**
- If the AS rejects: PASS (impersonation not allowed or agent-n not authorized)
- If the AS returns a token with `sub=alice` and no `act`: FAIL (unrestricted impersonation)
- If the AS returns a token with `sub=alice` and `act.sub=agent-n`: borderline (AS converted to delegation, which is acceptable)

**Why it matters:** Impersonation without explicit authorization is the most dangerous form of token exchange. An agent that can impersonate any user whose token it obtains gains full identity theft capability. RFC 8693 Section 5 warns that "any time one principal is delegated the rights of another principal, the potential for abuse is a concern."

---

#### TE-25: Timing Side-Channel on Chain Validation

**Severity:** Low
**RFC Reference:** None (operational security)
**Threat Catalog Reference:** INF-05

**Description:** Measure response times for exchanges with varying chain depths or token configurations. Significant timing differences can reveal:
- Whether the AS inspects nested `act` claims (timing increases with depth)
- Whether the AS performs signature validation on actor tokens (timing differs for valid vs invalid signatures)
- Whether the AS performs database lookups for certain token types

**Setup:** Perform multiple exchanges with varying parameters.

**Attack:** Statistical analysis of response times across different test vectors.

**Verify:** Informational -- flag significant timing variations.

**Why it matters:** Timing side-channels are a well-known class of information leakage. While low severity for this tool's primary purpose, noting timing anomalies can guide further manual analysis.

---

## Summary Matrix

| ID | Name | Severity | Priority | RFC Section |
|----|------|----------|----------|-------------|
| TE-01 | Token Type Indicator Mismatch | Critical | Must-have | 2.1 |
| TE-02 | Unauthenticated Token Exchange | Critical | Must-have | 5 |
| TE-03 | Requested Token Type Escalation | Critical | Must-have | 2.1 |
| TE-04 | Audience Targeting to Unauthorized Resource | Critical | Must-have | 2.1, 2.2.1 |
| TE-05 | `act` Claim Stripping / Delegation Downgrade | Critical | Must-have | 1.1, 4.1 |
| TE-06 | Expired Subject Token Acceptance | High | Should-have | 2.1 |
| TE-07 | Expired Actor Token Acceptance | High | Should-have | 2.1 |
| TE-08 | Circular Delegation Chain | High | Should-have | 4.1 |
| TE-09 | Delegation Chain Depth Exhaustion | High | Should-have | 4.1 |
| TE-10 | Issuer Validation on Subject Token | High | Should-have | 5 |
| TE-11 | Resource Parameter Abuse | High | Should-have | 2.1 |
| TE-12 | Downstream Token `aud` Verification | High | Should-have | 2.1 |
| TE-13 | Token Lifetime Reduction Verification | Medium | Should-have | 2.2 |
| TE-14 | `issued_token_type` Response Validation | Medium | Should-have | 2.2.1 |
| TE-15 | `act.sub` Matches Intended Actor | High | Should-have | 4.1 |
| TE-16 | `act` Claim Nesting Integrity | High | Should-have | 4.1 |
| TE-17 | Same Token as Both Subject and Actor | Medium | Nice-to-have | 2.1 |
| TE-18 | Missing `actor_token_type` | Medium | Nice-to-have | 2.1 |
| TE-19 | Refresh Token as Subject Token | Medium | Nice-to-have | 2.1, 3 |
| TE-20 | Missing Subject Token (Malformed) | Low | Nice-to-have | 2.1 |
| TE-21 | Replay of Previously Exchanged Token | Medium | Nice-to-have | 2.1 |
| TE-22 | Grant Type Confusion | Low | Nice-to-have | 2.1 |
| TE-23 | Malformed Token Fuzzing | Low | Nice-to-have | 2.1 |
| TE-24 | Impersonation Without Authorization | Medium | Nice-to-have | 1.1, 5 |
| TE-25 | Timing Side-Channel Analysis | Low | Nice-to-have | - |

---

## Implementation Priority

### Phase 1: Must-Have (5 tests) -- Required for credibility

These five tests address fundamental attack classes that are:
- Explicitly warned about in the RFC
- Validated by real-world CVEs (CVE-2022-1245, CVE-2025-55241)
- Absent from the current suite despite covering the most basic validation checks

1. **TE-02** (Unauthenticated Exchange) -- requires raw HTTP support
2. **TE-01** (Token Type Mismatch) -- uses existing infrastructure
3. **TE-03** (Requested Token Type Escalation) -- uses existing infrastructure
4. **TE-04** (Audience Targeting) -- requires "admin-service" config or config for unauthorized audience
5. **TE-05** (`act` Claim Stripping) -- uses existing infrastructure + JWT decode

### Phase 2: Should-Have (11 tests) -- Required for IETF submission quality

These tests cover the remaining significant attack surfaces and output validation:

6. **TE-15** (`act.sub` output validation) -- high value, easy to implement
7. **TE-12** (Downstream `aud` verification) -- validates mitigation profile #4
8. **TE-16** (`act` nesting integrity) -- requires multi-hop setup
9. **TE-08** (Circular delegation) -- requires additional client config
10. **TE-09** (Chain depth exhaustion) -- iterative test
11. **TE-10** (Issuer validation) -- requires JWT crafting capability
12. **TE-11** (Resource parameter abuse) -- uses existing infrastructure
13. **TE-06** (Expired subject token) -- requires delay or pre-expired token
14. **TE-07** (Expired actor token) -- requires delay or pre-expired token
15. **TE-13** (Token lifetime reduction) -- post-exchange JWT inspection
16. **TE-14** (`issued_token_type` validation) -- response field check

### Phase 3: Nice-to-Have (9 tests) -- Rounds out the suite

17-25. Edge cases, fuzzing, compliance, and informational tests.

---

## Infrastructure Requirements

Several proposed tests require capabilities not currently present in the tool:

| Capability | Needed By | Current Status |
|------------|-----------|---------------|
| Raw HTTP without client auth | TE-02 | Not supported -- `OAuthClient.applyClientAuth()` always runs |
| JWT creation/signing | TE-10, TE-23 | Not supported -- tool only consumes tokens |
| Pre-expired token input | TE-06, TE-07 | Not supported -- all tokens obtained fresh |
| Additional client configs | TE-08 (agent-b) | Supported via TOML config |
| `resource` parameter in exchange | TE-11 | Already supported in `TokenExchangeParams` |
| `requested_token_type` parameter | TE-03 | Already supported in `TokenExchangeParams` |
| Multiple successive exchanges | TE-08, TE-09, TE-16 | Supported but not used |
| JWT decode of output tokens | TE-05, TE-12, TE-13, TE-15, TE-16 | Available via `jose` (already a dependency) |
| Configurable "unauthorized" audience | TE-04 | Requires config extension |

---

## Cross-Reference: Threat Catalog Coverage After Remediation

If all 25 proposed tests are implemented alongside the existing 13:

| Threat Catalog ID | Status |
|-------------------|--------|
| ACT-01 (actor-client mismatch) | Covered by existing `actor-client-mismatch` |
| ACT-02 (nested act as authoritative) | Covered by TE-16 |
| ACT-03 (untrusted STS tokens) | Covered by TE-10 |
| ACT-04 (no max act depth) | Covered by TE-09 |
| ACT-05 (non-identity claims in act) | Covered by TE-16 |
| ACT-06 (act claim stripping) | Covered by TE-05 |
| ACT-07 (actor substitution) | Covered by TE-15 |
| ACT-08 (improper act construction) | Covered by TE-16 |
| CD-01 (no max chain depth) | Covered by TE-09 |
| CD-02 (scope not reduced) | Covered by existing `scope-escalation` |
| CD-04 (aud != sub at hop boundary) | Covered by existing `aud-sub-binding` |
| CD-07 (circular delegation) | Covered by TE-08 |
| CD-10 (chain splicing) | Covered by existing `basic-splice` |
| DI-01 (impersonation when delegation requested) | Covered by existing `delegation-impersonation-confusion` |
| DI-02 (no scope reduction on exchange) | Covered by existing `scope-escalation` + TE-24 |
| DI-03 (can't distinguish delegation from impersonation) | Covered by existing `delegation-impersonation-confusion` |

**Remaining uncovered from the threat catalog:** CD-03 (chronological ordering), CD-05 (unsigned chain steps), CD-06 (revocation cascade -- partially covered by existing `revocation-propagation`), CD-08 (chain-of-custody bypass), CD-09 (crypto DoS). These are either infeasible to test externally or require capabilities beyond the tool's scope.

---

## References

- [RFC 8693 -- OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 8693 Section 5 -- Security Considerations](https://www.rfc-editor.org/rfc/rfc8693.html#section-5)
- [RFC 9700 -- Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/rfc9700/)
- [IETF OAuth WG -- Delegation Chain Splicing Disclosure](http://www.mail-archive.com/oauth@ietf.org/msg25680.html)
- [IETF OAuth WG -- Response to Chain Splicing](http://www.mail-archive.com/oauth@ietf.org/msg25681.html)
- [CVE-2022-1245 -- Keycloak Token Exchange Privilege Escalation](https://github.com/keycloak/keycloak/security/advisories/GHSA-75p6-52g3-rqc8)
- [CVE-2025-55241 -- Microsoft Entra ID Actor Token Vulnerability](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)
- [Authlete -- RFC 8693 Implementation Guide](https://www.authlete.com/developers/token_exchange/)
- [Scott Brady -- Delegation Patterns for OAuth 2.0 using Token Exchange](https://www.scottbrady.io/oauth/delegation-patterns-for-oauth-20)
- [OAuth 2.0 Security Best Practices (WorkOS analysis)](https://workos.com/blog/oauth-best-practices)
