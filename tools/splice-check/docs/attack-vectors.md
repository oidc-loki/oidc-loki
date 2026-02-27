# splice-check Attack Vectors Reference

> **Who this is for:** Security researchers, penetration testers, and engineers who need to understand exactly what each test does, how it works, and what a pass or fail means.
>
> **Difficulty:** Advanced

This document provides full technical details for all 28 attack vectors in splice-check. Each entry includes the attack mechanism, the RFC section it tests, the three-phase execution flow, and the verdict logic.

## How Tests Work

Every test follows a three-phase lifecycle:

1. **Setup** — Obtain legitimate tokens via `client_credentials` grants. This establishes the honest baseline.
2. **Attack** — Craft and send a malicious token exchange request to the AS's token endpoint.
3. **Verify** — Inspect the AS's response and determine the verdict.

Verdicts:

| Verdict | Meaning |
|---------|---------|
| **PASS** | The AS correctly handled this attack (rejected it, or produced safe output) |
| **FAIL** | The AS is vulnerable — it accepted a request it should have rejected, or produced unsafe output |
| **SKIP** | Inconclusive — the AS returned an error unrelated to the test (401 auth error, 429 rate limit, 500 server error, or unsupported grant type) |

The response classification layer prevents false positives by distinguishing security rejections (400 `invalid_grant`, 403) from infrastructure errors (401, 429, 500). Infrastructure errors are always SKIP, never PASS.

---

## Baseline

### valid-delegation

| Field | Value |
|-------|-------|
| **ID** | `valid-delegation` |
| **Severity** | critical |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) |

**What it does:** Performs a legitimate token exchange — Alice's token exchanged by Agent A with proper authorization. This is the baseline: if it fails, the AS doesn't support token exchange at all, and all other tests are meaningless.

**Attack flow:**
1. Setup: obtain Alice's token and Agent A's token via `client_credentials`
2. Attack: send a standard delegation exchange (subject=Alice, actor=Agent A, client=Agent A)
3. Verify: expect HTTP 200 with `access_token` in response

**Verdict logic:**
- PASS: 200 with `access_token`
- FAIL: 200 without `access_token`, or any security rejection
- SKIP: auth error, rate limit, server error

---

## Core Splice Attacks

### basic-splice

| Field | Value |
|-------|-------|
| **ID** | `basic-splice` |
| **Severity** | critical |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) |

**What it does:** The canonical chain splicing attack. Presents `subject_token` from Chain 1 (Alice → Agent A) with `actor_token` from Chain 2 (Bob → Agent N). The AS should reject because `actor_token.sub` does not match `subject_token.aud`.

**Why it matters:** RFC 8693 Section 2.1 requires the AS to perform "appropriate validation" of both tokens, but does not explicitly mandate cross-chain validation. This is the gap that enables splicing.

**Verdict logic:**
- PASS: security rejection (400/403)
- FAIL: 200 with token issued (splice succeeded)
- SKIP: inconclusive responses

---

### actor-client-mismatch

| Field | Value |
|-------|-------|
| **ID** | `actor-client-mismatch` |
| **Severity** | critical |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) (act claim binding) |

**What it does:** Agent N authenticates as itself (with its own client credentials) but presents Agent A's token as the `actor_token`. The AS must verify that the authenticated client's identity matches the `actor_token.sub`.

**Why it matters:** Without client-actor binding, any client can claim to be acting as any other agent simply by obtaining or stealing their token.

---

### aud-sub-binding

| Field | Value |
|-------|-------|
| **ID** | `aud-sub-binding` |
| **Severity** | critical |
| **Spec** | [RFC 8693 Sections 2.1 + 4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) |

**What it does:** Exchanges a `subject_token` whose `aud` claim targets Agent A, but Agent N presents it. The AS must verify that the presenting actor's identity matches the token's intended audience.

**Why it matters:** The `aud` claim is the primary mechanism for binding a token to its intended recipient. If the AS doesn't check that the actor matches the audience, any agent can use any token.

---

### upstream-splice

| Field | Value |
|-------|-------|
| **ID** | `upstream-splice` |
| **Severity** | high |
| **Spec** | [RFC 8693 Sections 2.1 + 4.4](https://datatracker.ietf.org/doc/html/rfc8693#section-4.4) |

**What it does:** Agent A obtains a legitimate delegated token, then Agent N attempts to re-delegate it to itself. The AS should reject unauthorized re-delegation.

**Why it matters:** This tests whether the AS enforces downstream delegation restrictions. The `may_act` claim (Section 4.4) provides one mechanism, but the AS should also verify that re-delegation is authorized even without `may_act`.

---

### subject-actor-swap

| Field | Value |
|-------|-------|
| **ID** | `subject-actor-swap` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) |

**What it does:** Swaps `subject_token` and `actor_token` — presents the attacker's token as subject and the victim's token as actor. This inverts the delegation relationship: instead of "Agent acts for Alice," it produces "Alice acts for Agent."

---

## Input Validation Attacks

### token-type-mismatch

| Field | Value |
|-------|-------|
| **ID** | `token-type-mismatch` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) |

**What it does:** Presents an access_token but declares its `subject_token_type` as `urn:ietf:params:oauth:token-type:id_token`. The AS MUST validate that the token matches its declared type. Accepting mismatched types can lead to confused deputy attacks.

---

### unauthenticated-exchange

| Field | Value |
|-------|-------|
| **ID** | `unauthenticated-exchange` |
| **Severity** | critical |
| **Spec** | [RFC 8693 Section 5](https://datatracker.ietf.org/doc/html/rfc8693#section-5) |

**What it does:** Sends a token exchange request without any client authentication (no `client_id`, no `client_secret`, no Authorization header). RFC 8693 Section 5 explicitly warns: "Omitting client authentication allows for a compromised or malicious client to trade tokens."

**Verdict logic:**
- PASS: 401 (auth required), or 400 `invalid_client`, or 403
- FAIL: 200 (token issued without authentication)

---

### token-type-escalation

| Field | Value |
|-------|-------|
| **ID** | `token-type-escalation` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) |

**What it does:** Requests a `refresh_token` via `requested_token_type` when exchanging an access_token. An AS should not convert short-lived access credentials into long-lived refresh credentials through token exchange.

**Verdict logic:**
- PASS: rejection, or 200 with `issued_token_type` = `access_token` (AS constrained the output)
- FAIL: 200 with `refresh_token` in response or `issued_token_type` = `refresh_token`

---

### audience-targeting

| Field | Value |
|-------|-------|
| **ID** | `audience-targeting` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) / [CVE-2022-1245](https://nvd.nist.gov/vuln/detail/CVE-2022-1245) |

**What it does:** Agent N requests a token targeting an unauthorized audience. The AS must validate that the client is authorized for the specified audience. This directly relates to CVE-2022-1245 (Keycloak), where audience targeting was insufficiently validated.

---

### act-claim-stripping

| Field | Value |
|-------|-------|
| **ID** | `act-claim-stripping` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1) / CVE-2025-55241 |

**What it does:** Re-exchanges a delegation token (which has an `act` claim) without providing an `actor_token`. If the AS strips the `act` claim from the result, the delegation token becomes an impersonation token — indistinguishable from Alice's own direct token.

**Why it matters:** This converts a delegation (auditable, traceable) into an impersonation (invisible). CVE-2025-55241 describes this exact vulnerability.

---

### resource-abuse

| Field | Value |
|-------|-------|
| **ID** | `resource-abuse` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) |

**What it does:** Requests a token exchange with the `resource` parameter targeting an internal service URI (`https://internal-admin-api.corp.example.com`). The AS must validate that the client is authorized for the specified resource.

---

## Token Forgery Attacks

### issuer-validation

| Field | Value |
|-------|-------|
| **ID** | `issuer-validation` |
| **Severity** | critical |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) |

**What it does:** Submits a fabricated unsigned JWT with `iss: "https://evil-issuer.example.com"` as the `subject_token`. The AS must reject tokens from unrecognized issuers. A failure here means the AS accepts tokens it didn't issue — complete trust boundary violation.

**Implementation note:** Uses an unsigned JWT (`alg: none`) to test issuer validation independently of signature validation.

---

### expired-token-exchange

| Field | Value |
|-------|-------|
| **ID** | `expired-token-exchange` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) |

**What it does:** Submits a fabricated JWT with `exp` set to September 2001 (clearly expired). The AS must reject expired tokens to prevent credential re-activation. If accepted, attackers can replay old tokens indefinitely.

---

## Edge Case Variants

### multi-audience

| Field | Value |
|-------|-------|
| **ID** | `multi-audience` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) + [RFC 7519 Section 4.1.3](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3) |

**What it does:** Tests whether the AS properly handles `subject_token`s with multi-valued `aud` arrays. A permissive "is actor IN aud" check can enable splice attacks by accepting any token where the actor appears anywhere in the audience list.

---

### missing-aud

| Field | Value |
|-------|-------|
| **ID** | `missing-aud` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) + [RFC 7519 Section 4.1.3](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3) |

**What it does:** Attempts exchange with a `subject_token` that lacks an `aud` claim entirely. Without `aud`, the AS cannot perform audience/subject binding validation, making the token usable by any presenter.

---

### may-act-enforcement

| Field | Value |
|-------|-------|
| **ID** | `may-act-enforcement` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 4.4](https://datatracker.ietf.org/doc/html/rfc8693#section-4.4) |

**What it does:** Verifies that the AS enforces the `may_act` claim by rejecting exchanges from actors not listed in the subject_token's `may_act`. The `may_act` claim (Section 4.4) explicitly declares which actors are authorized to act on behalf of the subject.

**Note:** If the AS doesn't support `may_act`, the test skips rather than fails — `may_act` is an optional mechanism.

---

### scope-escalation

| Field | Value |
|-------|-------|
| **ID** | `scope-escalation` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) (scope parameter) |

**What it does:** Requests a broader scope (`openid profile admin write delete`) during token exchange than what the original `subject_token` allows. The AS should reject or constrain the scope to prevent privilege escalation.

**Verdict logic:**
- PASS: rejection (400 `invalid_scope`), or 200 with constrained scope (no admin/write/delete keywords)
- FAIL: 200 with escalated scope retained, or 200 with no scope in response (cannot verify constraint)

---

### delegation-impersonation-confusion

| Field | Value |
|-------|-------|
| **ID** | `delegation-impersonation-confusion` |
| **Severity** | high |
| **Spec** | [RFC 8693 Sections 1.1 + 4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-1.1) |

**What it does:** Performs an exchange with an `actor_token` and verifies the resulting token contains an `act` claim. RFC 8693 Section 1.1 distinguishes delegation (`actor_token` present → `act` claim in result) from impersonation (no `actor_token` → no `act` claim). If the AS omits `act` when `actor_token` was provided, it produces impersonation tokens instead of delegation tokens.

**Why it matters:** Without `act`, downstream services cannot distinguish "Alice is making this request" from "Agent A is making this request on Alice's behalf." This breaks audit trails and authorization policy enforcement.

---

## Output Validation Tests

These tests inspect the **content** of successfully issued tokens rather than testing whether the AS rejects malicious requests.

### issued-token-type-validation

| Field | Value |
|-------|-------|
| **ID** | `issued-token-type-validation` |
| **Severity** | medium |
| **Spec** | [RFC 8693 Section 2.2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.1) |

**What it does:** Verifies that the token exchange response includes the REQUIRED `issued_token_type` field with a recognized token type URI. This is a MUST-level requirement in RFC 8693. An AS that omits it violates the specification.

---

### downstream-aud-verification

| Field | Value |
|-------|-------|
| **ID** | `downstream-aud-verification` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) / 8-Point Mitigation Profile #4 |

**What it does:** Decodes the resulting JWT and checks that it has a constrained `aud` claim. Tokens without audience restriction are bearer tokens usable at any resource server — defeating the purpose of scoped delegation.

**Note:** Skips when the token is opaque (not a JWT) since claims cannot be inspected.

---

### token-lifetime-reduction

| Field | Value |
|-------|-------|
| **ID** | `token-lifetime-reduction` |
| **Severity** | medium |
| **Spec** | [RFC 8693 Section 2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2) / [RFC 9700](https://datatracker.ietf.org/doc/rfc9700/) |

**What it does:** Compares the `exp` claim of the delegated token against the original. RFC 8693 Section 2.2 and RFC 9700 recommend that delegated tokens have equal or shorter lifetimes. If exchange extends the lifetime, delegation becomes a persistence mechanism — an attacker can indefinitely extend access by repeatedly exchanging tokens.

---

### act-sub-verification

| Field | Value |
|-------|-------|
| **ID** | `act-sub-verification` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1) |

**What it does:** Verifies that the resulting token's `act.sub` claim matches the actor that was specified in the exchange request. A buggy AS might set `act.sub` to the wrong value (e.g., the subject instead of the actor), corrupting the delegation chain.

---

### act-nesting-integrity

| Field | Value |
|-------|-------|
| **ID** | `act-nesting-integrity` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1) |

**What it does:** Performs a multi-hop delegation (Alice → Agent A → Agent N) and verifies the resulting token's `act` chain correctly reflects the delegation history. Also checks that non-identity claims (`exp`, `nbf`, `iat`, `aud`, `iss`, `jti`, `scope`) are NOT leaked into `act` objects — `act` should only contain identity claims (`sub`, `act`).

---

## Delegation Chain Integrity Tests

### circular-delegation

| Field | Value |
|-------|-------|
| **ID** | `circular-delegation` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1) |

**What it does:** Creates a delegation chain A→N, then attempts to re-delegate back to A, forming a circular chain (A→N→A). Without cycle detection, circular delegation can cause infinite validator loops, unbounded chain growth, or confused authorization decisions.

**Setup flow:**
1. Obtain Alice's token
2. Delegate Alice → Agent A (hop 1)
3. Delegate hop1 → Agent N (hop 2)
4. Attack: attempt to delegate hop2 → Agent A (circular!)

---

### chain-depth-exhaustion

| Field | Value |
|-------|-------|
| **ID** | `chain-depth-exhaustion` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1) |

**What it does:** Performs 5 successive delegation exchanges, alternating between agents, to test whether the AS enforces a maximum chain depth. Each hop adds a nested `act` layer to the JWT. Without a maximum depth policy, iterative chaining creates token bloat, potential parser crashes, and denial-of-service vectors.

**Setup flow:**
1. Obtain Alice's token
2. Exchange: Alice → agent-a (depth 1)
3. Exchange: depth1 → agent-n (depth 2)
4. Exchange: depth2 → agent-a (depth 3)
5. Exchange: depth3 → agent-n (depth 4)
6. Attack: attempt depth 5

If the AS rejects at any depth during setup, the test passes immediately.

---

## Operational Security Tests

### refresh-bypass

| Field | Value |
|-------|-------|
| **ID** | `refresh-bypass` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) + [RFC 6749 Section 6](https://datatracker.ietf.org/doc/html/rfc6749#section-6) |

**What it does:** Revokes the original `subject_token`, then attempts to refresh a delegated token using the `refresh_token` obtained from the exchange. The AS should reject the refresh because the original delegation context has been invalidated.

**Why it matters:** If refresh tokens survive upstream revocation, an attacker who obtained a delegated token retains access indefinitely even after the user's session is revoked.

---

### revocation-propagation

| Field | Value |
|-------|-------|
| **ID** | `revocation-propagation` |
| **Severity** | high |
| **Spec** | [RFC 8693 Section 2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.1) + [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) |

**What it does:** Revokes the original `subject_token` via the revocation endpoint (RFC 7009), then introspects the downstream delegated token via the introspection endpoint (RFC 7662). The delegated token should be inactive — revocation should propagate through the delegation chain.

**Note:** Requires `revocation_endpoint` and `introspection_endpoint` to be configured. If not available, the test will fail during setup.

---

## Response Classification

splice-check classifies every AS response to prevent false positives:

| HTTP Status | Error Code | Classification | Effect |
|-------------|------------|----------------|--------|
| 200 | — | `success` | Test-specific verdict |
| 400 | `invalid_grant` | `security_rejection` | PASS for attack tests |
| 400 | `invalid_scope` | `security_rejection` | PASS for attack tests |
| 400 | `invalid_request` | `security_rejection` | PASS for attack tests |
| 400 | `invalid_client` | `auth_error` | SKIP (client config issue) |
| 400 | `unsupported_grant_type` | `unsupported` | SKIP (AS doesn't support exchange) |
| 401 | — | `auth_error` | SKIP |
| 403 | — | `security_rejection` | PASS for attack tests |
| 429 | — | `rate_limit` | SKIP |
| 500+ | — | `server_error` | SKIP |

This classification is critical: a 401 during an attack test is **not** a security rejection (it's likely a client credentials issue), and treating it as PASS would be a false positive.

---

## Further Reading

- [What Is Chain Splicing?](what-is-chain-splicing.md) — Non-technical overview
- [RFC 8693 Gap Analysis](rfc8693-gap-analysis.md) — Formal specification gaps enabling these attacks
- [Security Posture Assessment](security-posture-assessment.md) — Risk scoring and compliance mapping

---

*splice-check is part of the [oidc-loki](https://github.com/oidc-loki/oidc-loki) project. For authorized security testing only.*
