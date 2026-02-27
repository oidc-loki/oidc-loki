# Adversarial Review: splice-check CLI Tool

**Date:** 2026-02-27
**Reviewer:** Claude Opus 4.6 (adversarial pen-test review)
**Scope:** Full codebase review of `tools/splice-check/` -- 15 source files
**Context:** Security testing CLI validating OAuth 2.0 AS resistance to delegation chain splicing (RFC 8693)

---

## Executive Summary

The splice-check CLI is a well-architected, cleanly implemented tool with a sound three-phase test lifecycle (`setup -> attack -> verify`). The code is TypeScript-strict, well-documented, and follows the plan from `001-splice-check-cli.md` faithfully.

However, this adversarial review identifies **23 findings** across five categories: RFC compliance gaps, security concerns in the tool itself, missing test scenarios, coverage gaps against the 8-point mitigation profile, and code quality issues. Seven findings are rated **Critical** or **High** because they represent either false-negative risks (the tool reports "pass" when the AS is actually vulnerable) or credential exposure risks.

---

## 1. RFC 8693 Compliance Issues

### 1.1 [HIGH] Missing `resource` Parameter Support

RFC 8693 Section 2.1 defines the `resource` parameter for indicating the target service where the token will be used. The `TokenExchangeParams` interface in `client.ts` (line 219-229) omits `resource` entirely. This matters because:

- Some AS implementations use `resource` as the primary audience scoping mechanism (distinct from `audience`)
- An AS that validates delegation context via `resource` binding would not be testable
- The RFC explicitly distinguishes `resource` (physical location URI) from `audience` (logical identifier)

**File:** `/Users/cbc/code/apps/oidc-loki/tools/splice-check/src/client.ts` lines 219-229

```typescript
export interface TokenExchangeParams {
    subject_token: string;
    subject_token_type: string;
    actor_token?: string;
    actor_token_type?: string;
    audience?: string;
    scope?: string;
    requested_token_type?: string;
    clientName?: string;
    // MISSING: resource?: string;
}
```

**Recommendation:** Add `resource?: string | string[]` to `TokenExchangeParams`. RFC 8693 Section 2.1 allows multiple `resource` values.

### 1.2 [MEDIUM] `audience` Parameter Should Support Multiple Values

RFC 8693 Section 2.1 states that `audience` can appear multiple times in the request (like `resource`). The current implementation only supports a single string value. While `URLSearchParams` would need `.append()` calls for multi-valued parameters, the interface constrains this.

**File:** `/Users/cbc/code/apps/oidc-loki/tools/splice-check/src/client.ts` line 79

```typescript
if (params.audience !== undefined) {
    body.set("audience", params.audience);  // Only sets one value
}
```

### 1.3 [MEDIUM] No Support for `private_key_jwt` or `tls_client_auth`

The `AuthConfig` type in `config.ts` (line 36) only supports `client_secret_post` and `client_secret_basic`. The plan document mentions `private_key_jwt` but it was not implemented. Many production AS deployments (especially those concerned about delegation security) require `private_key_jwt` (RFC 7523) or `tls_client_auth` (RFC 8705).

**File:** `/Users/cbc/code/apps/oidc-loki/tools/splice-check/src/config.ts` lines 35-37

```typescript
export interface AuthConfig {
    method: "client_secret_post" | "client_secret_basic";
    // MISSING: "private_key_jwt" | "tls_client_auth"
}
```

**Impact:** The tool cannot test any AS that mandates mTLS or JWT-based client authentication, which excludes many FAPI-compliant deployments.

### 1.4 [LOW] `issued_token_type` Not Validated in Responses

RFC 8693 Section 2.2.1 requires the response to include `issued_token_type` indicating the type of the token that was issued. None of the tests validate this field. The `valid-delegation` test (line 43) only checks for `access_token` presence but not `issued_token_type`. A compliant implementation MUST return this field.

### 1.5 [LOW] No `SAML` Token Type Constants

RFC 8693 Section 3 defines two additional token type URIs for SAML assertions. While unlikely to be needed for this tool's use case, their absence means the `TOKEN_TYPE` constant object is incomplete relative to the RFC.

---

## 2. Security Concerns (Tool Itself)

### 2.1 [CRITICAL] Tokens Logged in Verbose Mode Without Redaction

When `verbose` is enabled, the test runner logs messages that include metadata about tokens obtained. More critically, individual tests log token values and claims via `ctx.log()`. For example:

**File:** `/Users/cbc/code/apps/oidc-loki/tools/splice-check/src/tests/missing-aud.ts` line 33

```typescript
ctx.log(`Alice's token has aud: ${hasAud} (value: ${JSON.stringify(claims.aud)})`);
```

While this specific line logs claims rather than raw tokens, the `setup` phases obtain raw access tokens and store them in `SetupResult.tokens`. The verbose log lines like `[setup] Obtained 2 token(s)` are benign, but the JSON output format (`reporter.ts` line 82-83) includes `logs` in the output:

```typescript
logs: r.logs.length > 0 ? r.logs : undefined,
```

If any test author adds `ctx.log(token)` (which is a natural debugging step), those tokens would appear in JSON/markdown output. There is no redaction layer.

**Recommendation:**
1. Add a `redactTokens(msg: string, tokens: Record<string, string>)` helper that replaces known token values with `[REDACTED:<name>]`
2. Apply it in the `log` function created in `runner.ts` line 98-102
3. Never include raw `logs` in JSON output unless `--verbose` is explicitly set

### 2.2 [HIGH] Client Secrets in Config File Without Encryption or Warning

The TOML config file contains `client_secret` values in plaintext. While this is standard for config files, the tool provides no:

- Warning about file permissions (should be `600` or `400`)
- Support for environment variable interpolation (e.g., `client_secret = "$ALICE_SECRET"`)
- Support for external secret references (e.g., `client_secret = "vault:secret/splice-check/alice"`)

**File:** `/Users/cbc/code/apps/oidc-loki/tools/splice-check/src/config.ts` lines 70-82

**Recommendation:** At minimum, support `${ENV_VAR}` interpolation in config values. Many security tools (Nuclei, ZAP) support this pattern. Add a startup warning if the config file has world-readable permissions.

### 2.3 [HIGH] No TLS Certificate Verification Controls

The `client.ts` uses Node.js `fetch()` with no TLS configuration. When testing against local/dev AS instances (common with Docker), users will likely need to:

- Disable certificate verification for self-signed certs
- Specify custom CA bundles
- Use mTLS client certificates

Currently, the only way to disable TLS verification is the global `NODE_TLS_REJECT_UNAUTHORIZED=0` environment variable, which is a blunt instrument that disables TLS for the entire process.

**Recommendation:** Add a `[target.tls]` config section:

```toml
[target.tls]
verify = true           # Set to false for self-signed certs
ca_bundle = "./ca.pem"  # Custom CA
```

### 2.4 [MEDIUM] No Request Timeout

The `fetch()` calls in `client.ts` have no timeout. A non-responsive AS endpoint will cause the tool to hang indefinitely.

**File:** `/Users/cbc/code/apps/oidc-loki/tools/splice-check/src/client.ts` lines 169-173

```typescript
const response = await fetch(endpoint, {
    method: "POST",
    headers,
    body: params.toString(),
    // MISSING: signal: AbortSignal.timeout(30000)
});
```

**Recommendation:** Add `signal: AbortSignal.timeout(config.timeout ?? 30000)` and make timeout configurable.

### 2.5 [MEDIUM] Revocation Endpoint Derivation Is Fragile

The `revokeToken` method (line 117) derives the revocation endpoint by replacing `/token` with `/revoke` in the token endpoint URL:

```typescript
const revocationEndpoint = this.target.token_endpoint.replace(/\/token$/, "/revoke");
```

This is fragile because:
- Not all AS implementations follow this convention (e.g., Keycloak uses a completely different path)
- If the token endpoint doesn't end in `/token`, the replacement is a no-op and the revocation request goes to the token endpoint
- Same issue exists for `introspectToken` (line 133)

**Recommendation:** Add `revocation_endpoint` and `introspection_endpoint` as optional fields in `TargetConfig`. Fall back to the derivation if not provided, but log a warning.

### 2.6 [LOW] `btoa()` for Basic Auth Is Not URL-Safe

The `client_secret_basic` implementation (line 205) uses `btoa()`:

```typescript
headers.Authorization = `Basic ${btoa(`${client.client_id}:${client.client_secret}`)}`;
```

Per RFC 6749 Section 2.3.1, the `client_id` and `client_secret` must be URL-encoded before being concatenated and base64-encoded. If either contains special characters (`:`, `%`, non-ASCII), this encoding is incorrect.

**Recommendation:** Use `encodeURIComponent()` on both values before concatenation:

```typescript
`Basic ${btoa(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`)}`
```

---

## 3. Missing Test Scenarios

### 3.1 [CRITICAL] No Test for `act.sub` vs Authenticated Client Mismatch (ACT-01)

The consolidated threat catalog identifies ACT-01 as Critical: "No validation that `act.sub` matches authenticated client -- actor impersonation." None of the 9 tests verify that the AS checks whether the `actor_token.sub` matches the authenticated client's identity. Specifically:

- Agent N authenticates with its own `client_id`/`client_secret`
- Agent N presents an `actor_token` with `sub=agent-a`
- The AS should reject because the authenticated client doesn't match the actor claim

This is the most direct form of actor impersonation and is absent from the test suite.

**Proposed test:** `actor-client-mismatch` -- authenticate as Client A but present Client B's token as `actor_token`.

### 3.2 [CRITICAL] No Test for Impersonation vs Delegation Confusion (DI-01)

RFC 8693 Section 1.1 distinguishes impersonation (no `actor_token`, resulting token has same `sub`) from delegation (`actor_token` provided, resulting token has `act` claim). The tool has no test that verifies:

- When `actor_token` is omitted, the AS treats it as impersonation (if allowed)
- When `actor_token` is present, the AS issues a proper delegation token with `act` claim
- The AS doesn't issue an impersonation token when delegation was requested

This confusion is rated Critical in the threat catalog (DI-01, DI-03).

**Proposed test:** `delegation-impersonation-confusion` -- exchange with `actor_token` and verify the response contains an `act` claim.

### 3.3 [HIGH] No Test for Scope Escalation Through Exchange (CD-02)

The threat catalog identifies CD-02 as Critical: "Scope not reduced at each hop -- privilege accumulation." None of the tests verify that:

- A delegated token has equal or reduced scope compared to the `subject_token`
- An exchange requesting broader scope than the `subject_token` allows is rejected

**Proposed test:** `scope-escalation` -- exchange Alice's token (scope: `read`) requesting scope: `read write admin`.

### 3.4 [HIGH] No Test for Token Type Indicator Mismatch

RFC 8693 Section 2.1 requires that `subject_token_type` accurately describes the type of `subject_token`. No test verifies what happens when:

- An access token is presented with `subject_token_type: urn:ietf:params:oauth:token-type:id_token`
- A JWT is presented with `subject_token_type: urn:ietf:params:oauth:token-type:refresh_token`

A permissive AS that ignores the type indicator might accept tokens it should reject.

**Proposed test:** `token-type-mismatch` -- present access_token but declare it as id_token type.

### 3.5 [HIGH] No Test for Circular Delegation (CD-07)

Can Agent A delegate to Agent B, which then re-delegates back to Agent A? This creates an infinite delegation loop. The tool should test whether the AS enforces maximum chain depth or detects circular references.

**Proposed test:** `circular-delegation` -- A -> B -> A delegation chain.

### 3.6 [MEDIUM] No Test for Expired Token Acceptance

No test verifies that the AS rejects expired `subject_token` or `actor_token` values in exchange requests. While this seems obvious, a misconfigured AS might not validate token expiry during exchange (validating only the grant parameters).

### 3.7 [MEDIUM] No Test for Cross-Issuer Token Exchange

In federated scenarios, the `subject_token` might come from a different issuer than the AS performing the exchange. The tool assumes a single issuer. Testing cross-issuer behavior is important for mitigation point #7 (issuer federation context validation).

### 3.8 [MEDIUM] No Test for Subject/Actor Token Role Swap

What happens when the attacker swaps the `subject_token` and `actor_token` -- presenting Alice's token as `actor_token` and Agent N's token as `subject_token`? This inverts the delegation relationship and should be rejected.

**Proposed test:** `subject-actor-swap`

### 3.9 [LOW] No Test for Unauthenticated Exchange

Does the AS reject token exchange requests with no client authentication at all? While simple, this is a basic security check that should be part of any conformance suite.

---

## 4. Coverage Against the 8-Point Mitigation Profile

The 8-point mitigation profile from `004-spec-contribution.md` is:

| # | Mitigation Point | Test Coverage | Gap? |
|---|-----------------|---------------|------|
| 1 | AS MUST verify `subject_token.aud` matches `actor_token.sub` at each exchange | `aud-sub-binding` (partial), `basic-splice` | **Partial** -- see 4.1 |
| 2 | For delegation chains, `subject_token` MUST carry single-valued `aud` | `multi-audience` | Covered |
| 3 | AS MUST validate delegation against policy (`may_act` or equivalent) | `may-act-enforcement` | **Weak** -- see 4.2 |
| 4 | AS SHOULD issue new token with `aud` set to intended downstream actor | None | **Missing** -- see 4.3 |
| 5 | Short token lifetimes + back-channel revocation | `revocation-propagation` (partial) | **Partial** -- see 4.4 |
| 6 | Refresh tokens from delegated exchange MUST re-validate delegation context | `refresh-bypass` | **Weak** -- see 4.5 |
| 7 | AS MUST validate issuer federation context in cross-domain scenarios | None | **Missing** -- see 4.6 |
| 8 | Failed splice validation MUST be logged as high-severity security event | None | **Missing** -- see 4.7 |

### 4.1 [HIGH] Mitigation #1: `aud`/`sub` Binding Verification Is Indirect

The `aud-sub-binding` test creates an audience-scoped token and then has the wrong actor present it, which is good. However, it does not **positively verify** that the AS is performing `aud`/`sub` matching. The test passes if the AS rejects the request for *any* reason (status >= 400). The AS might reject because:

- It doesn't support actor tokens at all
- The client is not authorized for token exchange
- Rate limiting kicked in

A false positive is possible. The test should ideally verify the error response body contains a relevant error code (`invalid_grant`, `invalid_target`, or similar) that indicates **why** it was rejected.

**Recommendation:** Check `response.body.error` in the verify phase. A rejection with `invalid_client` is not the same as a rejection with `invalid_grant` due to aud/sub mismatch.

### 4.2 [MEDIUM] Mitigation #3: `may_act` Test Depends on Token Content

The `may-act-enforcement` test inspects Alice's token to see if it contains `may_act`. If it doesn't, the test is skipped. This is reasonable, but there's no way to **force** the AS to issue tokens with `may_act` claims. The test will always skip on AS implementations that don't support `may_act`, which is the common case.

**Recommendation:** Add a config option `[target.capabilities]` that lets the operator declare which features the AS supports. If `may_act = true`, the test can fail instead of skip when the claim is missing.

### 4.3 [HIGH] Mitigation #4: No Test for Downstream `aud` Setting

Mitigation #4 says the AS SHOULD set the `aud` of the newly issued token to the intended downstream actor. No test verifies this. After a successful exchange, the resulting token's `aud` claim should be inspected.

**Proposed test:** Perform a valid exchange, decode the resulting JWT, and verify `aud` is set to the next downstream actor (or at minimum, is not the same as the original subject_token's aud).

### 4.4 [MEDIUM] Mitigation #5: No Lifetime Validation

No test checks whether delegated tokens have shorter lifetimes than the original `subject_token`. This is a SHOULD-level mitigation, but validating it would be straightforward: compare `exp` of the exchanged token against `exp` of the original.

### 4.5 [HIGH] Mitigation #6: Refresh Bypass Test Is Inconclusive

The `refresh-bypass` test acknowledges in its own `verify` function (lines 76-85) that it cannot actually test the core scenario: refreshing a delegated token **after the delegation has been revoked**. It always returns `passed: true` if the refresh succeeds, which provides no useful signal about delegation context re-validation.

```typescript
// Refresh succeeded — this is expected for a legitimate refresh.
// The real concern is whether the AS would still refresh after
// the delegation is revoked, which requires revocation testing.
return {
    passed: true,
    reason: "Refresh succeeded (expected for active delegation). " +
        "Full bypass testing requires revocation infrastructure...",
};
```

This is a false "pass." The test should either:
1. Actually revoke the original token before refreshing (combine with revocation-propagation logic), or
2. Be marked as `skipped` with a clear reason, not `passed`

**File:** `/Users/cbc/code/apps/oidc-loki/tools/splice-check/src/tests/refresh-bypass.ts` lines 73-85

### 4.6 [MEDIUM] Mitigation #7: No Cross-Domain Test Infrastructure

Issuer federation validation (mitigation #7) requires testing with tokens from a different issuer. The current config only supports a single target AS. Testing this would require either:
- A second AS instance in the config
- The ability to craft/import tokens from a foreign issuer

This is understandably complex, but should at minimum be documented as a known gap.

### 4.7 [LOW] Mitigation #8: No Way to Verify Security Event Logging

Mitigation #8 requires the AS to log failed splice attempts. This is inherently difficult to test externally, but a conformance test could:
- Make a splice attempt
- Check if the AS provides audit log endpoints
- At minimum, verify the HTTP response includes appropriate error codes and headers

---

## 5. Code Quality Issues

### 5.1 [MEDIUM] `valid-delegation` Failure Should Short-Circuit

The test index orders `valid-delegation` first (line 22-32 of `index.ts`), and the plan states "if it fails, nothing else matters." However, the runner does not implement short-circuit behavior. If the baseline fails, all subsequent tests will also fail with confusing setup errors rather than a clear "baseline failed, aborting" message.

**File:** `/Users/cbc/code/apps/oidc-loki/tools/splice-check/src/runner.ts` lines 70-77

```typescript
for (const test of filtered) {
    options.onTestStart?.(test);
    const result = await runSingleTest(test, config, client, options.verbose ?? false);
    results.push(result);
    options.onTestComplete?.(result);
    // MISSING: if (test.id === "valid-delegation" && !result.verdict.passed) break;
}
```

**Recommendation:** Add a `bail` option or check if the first test failed and mark all remaining as skipped.

### 5.2 [MEDIUM] Type Safety Gap in Response Body Casting

Multiple tests cast `response.body` to `Record<string, unknown>` without validation:

```typescript
const body = response.body as Record<string, unknown>;
const delegatedToken = body.access_token as string;
```

If the response body is a string (non-JSON error response), this cast silently produces `undefined`, which then propagates as a bug. The `client.ts` already handles JSON vs text parsing (lines 181-187), but the tests don't verify the type before casting.

**Recommendation:** Add a `assertJsonBody(response: AttackResponse)` helper that throws a clear error if the body is not an object.

### 5.3 [LOW] No Retry Logic for Transient Failures

Network errors, rate limiting (HTTP 429), and transient 503 errors will cause test failures that are not related to the AS's security posture. A single-retry with backoff for these status codes would improve reliability.

### 5.4 [LOW] Missing `process.exit()` Handler for Unhandled Rejections

The CLI catches `ConfigError` but other unhandled promise rejections (e.g., DNS resolution failure, connection refused) will produce cryptic Node.js stack traces instead of user-friendly error messages.

**File:** `/Users/cbc/code/apps/oidc-loki/tools/splice-check/src/cli.ts` lines 61-67

### 5.5 [LOW] Reporter Table Format Uses ASCII Art, Not Unicode

Minor: the table format uses `=`, `-`, `+`, `!` characters. Using Unicode box-drawing characters (`--`, `|`, etc.) and check/cross marks would improve terminal readability. The plan mentions `chalk` as an optional dependency but it was not included.

### 5.6 [LOW] No Support for `--dry-run`

There is no way to see what the tool would do without making HTTP requests. A `--dry-run` mode that logs the planned requests (with redacted credentials) would be useful for operators who need to verify configuration before running against production.

---

## 6. Summary of Findings

### By Severity

| Severity | Count | Key Issues |
|----------|-------|------------|
| Critical | 3 | Token logging without redaction, missing actor-client mismatch test, missing delegation/impersonation confusion test |
| High | 8 | No `resource` param, client secrets unprotected, no TLS controls, aud/sub verification indirect, refresh-bypass inconclusive, scope escalation untested, downstream aud untested, circular delegation untested |
| Medium | 8 | Multi-value audience, private_key_jwt, timeouts, endpoint derivation, short-circuit, type safety, may_act depends on token, no lifetime validation |
| Low | 4 | issued_token_type, SAML types, btoa encoding, no dry-run |

### By Category

| Category | Count |
|----------|-------|
| RFC 8693 Compliance | 5 |
| Tool Security | 6 |
| Missing Test Scenarios | 9 |
| 8-Point Mitigation Coverage | 7 |
| Code Quality | 6 |

---

## 7. Prioritized Recommendations

### Immediate (Before First Public Release)

1. **Add token redaction** to the verbose logging path (2.1)
2. **Fix refresh-bypass** to not report false "pass" -- either test properly or skip (4.5)
3. **Add `actor-client-mismatch` test** -- this is the most direct splice validation (3.1)
4. **Add error code validation** in verify phases -- don't accept any 4xx as "pass" (4.1)
5. **Add request timeouts** to prevent hangs (2.4)
6. **Add env var interpolation** for secrets in config (2.2)

### Before IETF Submission as Test Vectors

7. **Add `resource` parameter** support (1.1)
8. **Add `delegation-impersonation-confusion` test** (3.2)
9. **Add `scope-escalation` test** (3.3)
10. **Add downstream `aud` verification test** for mitigation #4 (4.3)
11. **Add `subject-actor-swap` test** (3.8)
12. **Support `private_key_jwt`** auth method (1.3)
13. **Add configurable endpoint overrides** for revocation/introspection (2.5)
14. **Implement baseline short-circuit** in runner (5.1)

### Future Enhancements

15. Support for cross-domain testing infrastructure (mitigation #7)
16. Add `--dry-run` mode
17. Retry logic for transient failures
18. Token type mismatch test
19. Circular delegation test
20. Expired token acceptance test

---

## 8. Architectural Assessment

Despite the findings above, the architecture is solid. The `AttackTest` interface with its three-phase lifecycle is well-designed and extensible. The separation of concerns between `client.ts` (HTTP mechanics), `runner.ts` (orchestration), `reporter.ts` (output), and individual test files is clean. The config-driven approach means the tool genuinely is AS-agnostic.

The most important structural improvement would be to add a **response classification layer** between the HTTP response and the test verdict. Currently, each test independently checks `status >= 400` and considers it a pass. This means:

- An AS that returns 401 (bad client auth) looks the same as one that returns 400 (properly rejected splice)
- An AS that returns 403 (forbidden) looks the same as one that returns 422 (validation error)
- Rate limiting (429) would be counted as a pass

A shared `classifyResponse(response)` function that distinguishes between "security rejection," "auth error," "server error," and "rate limit" would make all tests more accurate and reduce false positives.

---

## References

- [RFC 8693 -- OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 8693 Section 2.1 -- Token Exchange Request](https://www.rfc-editor.org/rfc/rfc8693.html#section-2.1)
- [RFC 6749 Section 2.3.1 -- Client Password](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1)
- [IETF OAuth WG -- Delegation Chain Splicing Disclosure](http://www.mail-archive.com/oauth@ietf.org/msg25680.html)
- [IETF OAuth WG -- Response to Chain Splicing](http://www.mail-archive.com/oauth@ietf.org/msg25684.html)
- [CVE-2025-55241 -- Microsoft Entra ID Actor Token Vulnerability](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)
- [draft-ietf-oauth-identity-chaining-08](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/)
- [OAuth 2.0 Security BCP (RFC 9700)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Authlete -- RFC 8693 Implementation Guide](https://www.authlete.com/developers/token_exchange/)
