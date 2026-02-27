# RFC 8693 Gap Analysis and Mitigation Profile

> **Who this is for:** Standards authors, IETF OAUTH-WG participants, AS implementers writing security documentation, and researchers analyzing delegation protocol safety.
>
> **Difficulty:** Expert

This document provides a section-by-section analysis of [RFC 8693 (OAuth 2.0 Token Exchange)](https://datatracker.ietf.org/doc/html/rfc8693) identifying specification gaps that enable delegation chain splicing attacks, cross-references with [RFC 9700 (OAuth 2.0 Security BCP)](https://datatracker.ietf.org/doc/rfc9700/), and proposes an 8-point mitigation profile with suggested normative language.

## Background

The delegation chain splicing vulnerability was disclosed to the IETF OAUTH-WG mailing list. The root cause: RFC 8693 describes a token exchange mechanism but does not mandate cross-validation between `subject_token` and `actor_token`. An authorization server that validates each token independently — as the spec describes — will accept spliced chains from unrelated trust contexts.

This analysis maps each specification gap to the splice-check test vectors that detect it, providing AS implementers with both the theoretical vulnerability and a concrete detection mechanism.

---

## Section-by-Section Analysis

### Section 1.1 — Delegation vs. Impersonation

**RFC text:** "Delegation semantics [...] the issued token would contain information about both the subject and the actor [...] An `act` (actor) claim [...] can be used for this purpose."

**Gap:** The specification describes delegation semantics and the `act` claim but uses "can be used" (permissive) rather than "MUST include" (normative). This allows AS implementations to issue delegation-style tokens without `act` claims, making them indistinguishable from impersonation tokens.

**Impact:** Downstream services cannot distinguish delegation from impersonation, breaking audit trails and policy enforcement.

**Test vectors:**
- `delegation-impersonation-confusion` — Verifies `act` claim presence in delegation output
- `act-claim-stripping` — Detects `act` claim removal during re-exchange (CVE-2025-55241)

**Suggested normative addition:**
> When the `actor_token` parameter is present in the request, the resulting token MUST include an `act` claim identifying the actor. The AS MUST NOT issue tokens that omit the `act` claim when delegation semantics were requested.

---

### Section 2.1 — Token Exchange Request

**RFC text:** "The authorization server MUST perform the appropriate validation procedures for the indicated token type and, if the actor token is unable to be validated, the authorization server MUST respond with an error."

**Gap 1: No cross-validation requirement.** The spec requires validation of each token independently ("appropriate validation procedures for the indicated token type") but never requires cross-validation between `subject_token` and `actor_token`. An AS can validate both tokens as individually legitimate and issue a spliced delegation.

**Impact:** This is the root cause of delegation chain splicing. Two tokens from unrelated trust contexts can be combined because the AS never verifies they belong to the same delegation flow.

**Test vectors:**
- `basic-splice` — Cross-chain subject + actor
- `actor-client-mismatch` — Client identity ≠ actor token identity
- `aud-sub-binding` — Subject token audience ≠ presenting actor
- `subject-actor-swap` — Inverted delegation relationship

**Suggested normative addition:**
> The authorization server MUST verify that the `actor_token` represents an entity authorized to act on behalf of the `subject_token`'s subject. This verification SHOULD include at least one of: (a) confirming the authenticated client's identity matches the `actor_token`'s subject claim, (b) confirming the `subject_token`'s `aud` claim includes the actor's identity, or (c) confirming the `subject_token`'s `may_act` claim (Section 4.4) authorizes the actor.

**Gap 2: No `resource` parameter validation requirement.** The `resource` parameter is described but no validation constraints are specified.

**Test vector:** `resource-abuse`

**Gap 3: No `audience` parameter validation requirement.** Similar to `resource`.

**Test vector:** `audience-targeting` (also CVE-2022-1245)

**Gap 4: Token type validation is underspecified.** "Appropriate validation procedures for the indicated token type" leaves implementation-defined what those procedures are.

**Test vector:** `token-type-mismatch`

---

### Section 2.2 — Token Exchange Response

**RFC text (Section 2.2.1):** "The `issued_token_type` [...] is a token type identifier [...] This is REQUIRED in the response."

**Gap:** While `issued_token_type` is correctly marked REQUIRED (a MUST-level keyword), the specification does not constrain the relationship between `requested_token_type` and `issued_token_type`. An AS may issue a `refresh_token` when an `access_token` was implicitly expected.

**Test vectors:**
- `issued-token-type-validation` — Verifies REQUIRED field presence
- `token-type-escalation` — Tests type escalation (access → refresh)

**RFC text (Section 2.2):** "The authorization server may need to apply appropriate policies [...] regarding the lifetime of the issued token."

**Gap:** "May need to" is not normative. The absence of a MUST-level lifetime constraint allows delegation to extend token lifetimes indefinitely, contradicting RFC 9700 Section 4.13 recommendations.

**Test vector:** `token-lifetime-reduction`

**Suggested normative addition:**
> The `exp` claim of a token issued via exchange MUST NOT exceed the `exp` claim of the `subject_token`. The authorization server SHOULD issue tokens with a shorter lifetime than the `subject_token` to account for delegation risk.

---

### Section 4.1 — act (Actor) Claim

**RFC text:** "A chain of delegation can be expressed by nesting one `act` claim within another."

**Gap 1: No nesting integrity requirements.** The spec describes nesting but does not specify what claims are permitted inside `act` objects. Implementations may leak non-identity claims (`exp`, `nbf`, `iat`, `aud`, `iss`, `jti`, `scope`) into `act`, creating confused deputy scenarios.

**Test vector:** `act-nesting-integrity`

**Gap 2: No `act.sub` accuracy requirement.** The spec does not require that `act.sub` correctly identify the actor from the exchange request.

**Test vector:** `act-sub-verification`

**Gap 3: No cycle detection requirement.** Nested `act` claims can create circular references (A→N→A) with no specified detection mechanism.

**Test vector:** `circular-delegation`

**Gap 4: No depth limit requirement.** Arbitrary nesting depth creates unbounded token growth and parser DoS vectors.

**Test vector:** `chain-depth-exhaustion`

**Suggested normative additions:**
> The `act` claim MUST contain only identity-related claims (`sub` and optionally a nested `act`). Non-identity claims such as `exp`, `nbf`, `iat`, `aud`, `iss`, `jti`, and `scope` MUST NOT appear inside `act` objects.
>
> The `act.sub` value MUST identify the actor specified in the token exchange request.
>
> The authorization server MUST detect and reject circular delegation chains (where an actor appears as both delegator and delegate in the same chain).
>
> The authorization server SHOULD enforce a maximum delegation chain depth. A depth limit of 3-5 is RECOMMENDED.

---

### Section 4.4 — may_act Claim

**RFC text:** "The `may_act` claim makes a statement that one party is authorized to become the actor [...] An example of such a claim is shown below."

**Gap:** The `may_act` claim is described with example syntax but its enforcement is entirely optional. The spec uses "makes a statement" rather than normative language. An AS that ignores `may_act` — even when present in the subject token — is technically compliant.

**Test vector:** `may-act-enforcement`

**Suggested normative addition:**
> When the `subject_token` contains a `may_act` claim, the authorization server MUST verify that the actor requesting delegation is listed in `may_act` before issuing a delegation token. If the actor is not authorized by `may_act`, the authorization server MUST reject the request.

---

### Section 5 — Security Considerations

**RFC text:** "Omitting client authentication allows for a compromised or malicious client to trade tokens."

**Gap:** Despite this explicit warning, client authentication is not a MUST-level requirement for the token exchange endpoint. The warning is informative, not normative.

**Test vector:** `unauthenticated-exchange`

**Suggested normative addition:**
> The token exchange endpoint MUST require client authentication. The authorization server MUST NOT issue exchanged tokens to unauthenticated clients.

---

## Cross-Reference: RFC 9700 (OAuth 2.0 Security BCP)

RFC 9700 (January 2025) provides updated security guidance but addresses token exchange only briefly:

| RFC 9700 Section | Relevance to Token Exchange | Covered by splice-check |
|---|---|---|
| 2.4 (Token Replay) | Delegated tokens must be audience-constrained | `downstream-aud-verification` |
| 4.1 (Client Authentication) | All endpoints should require client auth | `unauthenticated-exchange` |
| 4.9 (Scope) | Tokens should have minimal scope | `scope-escalation` |
| 4.13 (Token Lifetime) | Tokens should have limited lifetime | `token-lifetime-reduction` |

**Gap in RFC 9700:** No section addresses delegation chain integrity, chain splicing, or `act` claim validation. This represents a gap in the security BCP's coverage of the token exchange grant type.

---

## Cross-Reference: RFC 7009 and RFC 7662

Delegation creates derived tokens whose lifecycle depends on the original. Neither RFC 7009 (Token Revocation) nor RFC 7662 (Token Introspection) address revocation propagation through delegation chains.

**Test vectors:**
- `revocation-propagation` — Revoking original must invalidate derived tokens
- `refresh-bypass` — Refresh tokens must not survive upstream revocation

---

## 8-Point Mitigation Profile

Based on the gap analysis above, this mitigation profile provides a concrete checklist for AS implementers:

| # | Mitigation | RFC Gap | Test Vector(s) |
|---|-----------|---------|-----------------|
| 1 | **Cross-validate subject and actor.** Verify the actor is authorized to act on behalf of the subject via `aud` matching, `may_act` enforcement, or policy. | Section 2.1 (no cross-validation) | `basic-splice`, `aud-sub-binding`, `actor-client-mismatch` |
| 2 | **Bind actor identity to client.** The authenticated client MUST match the `actor_token.sub`. | Section 2.1 (no binding requirement) | `actor-client-mismatch` |
| 3 | **Require client authentication.** Token exchange endpoint MUST require authentication. | Section 5 (warning only) | `unauthenticated-exchange` |
| 4 | **Constrain output token audience.** Delegated tokens MUST have `aud` set to the intended downstream consumer. | Section 2.2 (no output constraints) | `downstream-aud-verification` |
| 5 | **Preserve delegation semantics.** When `actor_token` is present, result MUST include `act` claim. Re-exchange MUST NOT strip `act`. | Section 1.1 (permissive language) | `delegation-impersonation-confusion`, `act-claim-stripping` |
| 6 | **Constrain token lifetime.** Delegated token `exp` MUST NOT exceed original. | Section 2.2 / RFC 9700 | `token-lifetime-reduction` |
| 7 | **Enforce chain integrity.** Detect circular chains, limit depth, validate `act` nesting. | Section 4.1 (no integrity requirements) | `circular-delegation`, `chain-depth-exhaustion`, `act-nesting-integrity` |
| 8 | **Propagate revocation.** Revoking a source token MUST invalidate all derived tokens. | Not addressed in RFC 8693 | `revocation-propagation`, `refresh-bypass` |

---

## Applicable CVEs

| CVE | Description | Relevant Mitigation Points |
|-----|-------------|---------------------------|
| [CVE-2022-1245](https://nvd.nist.gov/vuln/detail/CVE-2022-1245) | Keycloak privilege escalation via audience targeting | #1, #4 |
| CVE-2025-55241 | `act` claim stripping during re-exchange | #5 |

---

## References

- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/rfc9700/) (January 2025)
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7009 — OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
- [RFC 7662 — OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [OAUTH-WG Mailing List: Delegation Chain Splicing](http://www.mail-archive.com/oauth@ietf.org/msg25680.html)

---

*splice-check is part of the [oidc-loki](https://github.com/oidc-loki/oidc-loki) project. For authorized security testing only.*
