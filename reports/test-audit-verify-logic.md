# Audit: verify() Logic in splice-check Attack Test Vectors

**Date:** 2026-02-27
**Scope:** All 13 attack test vectors + `classify.ts` + `test-vectors.test.ts`
**Auditor:** Claude Code (Opus 4.6)

---

## Executive Summary

The verify() logic is well-structured overall. The introduction of `classify.ts` as a shared classification layer is sound and prevents the most dangerous category of bugs (treating all 4xx as "pass"). However, this audit identified **5 confirmed bugs** (2 high severity, 3 medium severity), **3 design concerns** that could cause incorrect verdicts in production, and **significant test coverage gaps**.

---

## 1. classify.ts Analysis

### 1.1 SECURITY_REJECTION_ERRORS Set

Current members:
- `invalid_grant`
- `invalid_target`
- `invalid_request`
- `unauthorized_client`
- `access_denied`

**BUG (Medium): `invalid_scope` is missing.** RFC 6749 Section 5.2 defines `invalid_scope` as a standard error code. The `scope-escalation` test (Test 11) sends a request that could receive `error: "invalid_scope"` from a compliant AS. The test's unit test actually uses `makeResponse(400, { error: "invalid_scope" })` and expects `passed: true`. This works only because `classifyResponse()` falls through to the "400/403 without recognizable error code" default (line 66), which returns `"security_rejection"`. So **the test passes by accident**, not by correct classification. If the default were ever changed to `"unknown"`, the scope-escalation test would break silently.

**Recommendation:** Add `"invalid_scope"` to `SECURITY_REJECTION_ERRORS`.

**BUG (Medium): `unsupported_grant_type` is missing.** An AS that does not support `urn:ietf:params:oauth:grant-type:token-exchange` at all will return `unsupported_grant_type`. This is currently classified as `"security_rejection"` via the default path. While not a security rejection per se, it should at minimum be explicitly handled -- arguably it should be classified as `"unknown"` or a new category, since it means the AS simply does not support the feature being tested, and every attack test would falsely pass.

### 1.2 AUTH_ERROR_CODES Set

Current members:
- `invalid_client`

**This is correct but narrow.** There are no other standard OAuth error codes that exclusively indicate client authentication failure. However, some AS implementations return custom error codes for client auth issues (e.g., `client_not_found`). These would fall through to `"security_rejection"` for 400 responses, which is the safer default direction (would cause a false negative rather than a false positive).

### 1.3 Status Code Handling

| Status | Classification | Correct? |
|--------|---------------|----------|
| 200-299 | `success` | Yes |
| 429 | `rate_limit` | Yes |
| 500+ | `server_error` | Yes |
| 401 | `auth_error` | Yes |
| 400 | Inspects error code | Yes |
| 403 | Inspects error code | Yes |
| 302 | `unknown` | **Concern** (see below) |
| 404 | `unknown` | **Concern** (see below) |
| 408 | `unknown` | **Concern** (see below) |

**Design Concern: HTTP 302/3xx redirects.** If an AS redirects the token endpoint request (e.g., load balancer redirect, misconfigured endpoint), this gets classified as `"unknown"`. In most attack tests, `"unknown"` falls through to the `passed: false` branch (not `skipped`), meaning a redirect would be reported as a vulnerability. This is a false negative -- the AS is not vulnerable; it is misconfigured.

**Design Concern: HTTP 404.** If the token exchange endpoint does not exist (404), this is classified as `"unknown"`. Same issue as redirects -- the test would report a failure/vulnerability rather than skipping.

**Design Concern: HTTP 408 Request Timeout.** This gets `"unknown"` and could produce a false negative.

**Recommendation:** Consider adding `"unknown"` to the `isInconclusive()` function, or handle 3xx and 404 explicitly.

### 1.4 extractErrorCode Robustness

```typescript
function extractErrorCode(response: AttackResponse): string | undefined {
    if (response.body !== null && typeof response.body === "object") {
        const body = response.body as Record<string, unknown>;
        if (typeof body.error === "string") {
            return body.error;
        }
    }
    return undefined;
}
```

**This is correct** for the standard OAuth error response format. It safely handles:
- `null` body
- Non-object body (string, number)
- Object body without `error` key
- Object body with non-string `error`

**Edge case not handled:** Array body. `typeof [] === "object"` and `Array.isArray` is not checked here (though `jsonBody()` does check it). If `body` is `[{error: "invalid_grant"}]`, `body.error` would be `undefined` (arrays don't have `.error`), so it safely returns `undefined`. Not a bug, but worth noting.

---

## 2. Per-Test verify() Analysis

### Test 0: valid-delegation

```typescript
verify(response) {
    if (response.status === 200) {
        const body = response.body as Record<string, unknown>;
        if (body.access_token) { return { passed: true, ... }; }
        return { passed: false, ... };
    }
    return { passed: false, ... };
}
```

**BUG (High): Does not use classify.ts at all.** This is the baseline test. It checks only for `status === 200`. Problems:

1. **A 401 (invalid_client / misconfigured client) returns `passed: false`** with reason "AS rejected valid delegation." This is correct behavior in isolation (the baseline DID fail), but the test provides no way to distinguish "the AS has a security policy that rejects this" from "the client credentials are wrong." The operator sees "FAIL: AS rejected valid delegation" and may conclude the AS is broken when in reality the test config is wrong.

2. **A 429 or 500 returns `passed: false`** instead of `skipped`. This means transient infrastructure issues cause the baseline to report failure, which cascades (all other tests depend on this baseline).

3. **The `body` cast on line 42 is unsafe.** If `response.body` is `null`, `"text"`, or an array, the cast to `Record<string, unknown>` succeeds at the type level but `body.access_token` would be `undefined` for most of these. For `null`, it would throw at runtime (`Cannot read properties of null`).

**Recommendation:** Use `jsonBody()` from classify.ts for safe body extraction. Consider adding `isInconclusive()` handling to return `skipped` for infrastructure issues.

### Test 1: basic-splice

**Correct.** Uses the standard `isSecurityRejection -> isInconclusive -> fail` pattern. No bugs found.

False positive risk: None. `isSecurityRejection` properly distinguishes 400/403 security rejections from 401 auth errors.
False negative risk: An AS returning HTTP 302 or 404 would report as `passed: false` (vulnerability) instead of `skipped`. Low probability.

### Test 2: aud-sub-binding

**Correct.** Same pattern as basic-splice. No additional concerns.

### Test 3: upstream-splice

**Correct.** Same pattern. No additional concerns.

### Test 4: multi-audience

**Correct.** The conditional logic on `hasMultiAud` metadata is sound. When the token does not have multi-valued aud, the test still correctly reports failure if the AS accepts (since it is still a cross-chain exchange that should be rejected).

### Test 5: missing-aud

**Correct.** Similar conditional logic on `hasAud` metadata. The differentiated failure messages correctly distinguish "accepted without aud" from "accepted despite aud presence."

### Test 6: may-act-enforcement

**BUG (High): Overly broad pass condition bypasses classification.**

```typescript
// When hasMayAct is false:
if (response.status >= 400) {
    return { passed: true, reason: `AS rejected exchange — ${describeResponse(response)}` };
}

// When hasMayAct is true:
if (response.status >= 400) {
    return { passed: true, reason: `AS rejected unauthorized actor — ${describeResponse(response)}` };
}
```

Lines 74 and 96: The `response.status >= 400` checks count **any** 4xx/5xx as a "pass." This means:

- **HTTP 401 (invalid_client)** = `passed: true`. This is a false positive. The AS did not enforce may_act; it rejected the client auth. The test should report `skipped`.
- **HTTP 429 (rate limited)** = `passed: true`. False positive. The request was rate-limited, not policy-rejected.
- **HTTP 500 (server error)** = `passed: true`. False positive. The server crashed; that is not a security rejection.

This is the most serious bug found. It means `may-act-enforcement` can report "pass" when the AS is actually broken or misconfigured, giving operators false confidence.

**Recommendation:** Replace `response.status >= 400` with `isSecurityRejection(response)` and add `isInconclusive()` handling.

### Test 7: refresh-bypass

**BUG (Medium): Same `response.status >= 400` overbroad pass pattern.**

```typescript
if (response.status >= 400) {
    return { passed: true, reason: `AS rejected refresh after upstream revocation — ${describeResponse(response)}` };
}
```

Line 94: A 401 (client auth failure), 429 (rate limit), or 500 (server error) all count as "pass." Same false positive risk as may-act-enforcement.

**Note:** The `isSecurityRejection` check on line 87 is redundant with the `>= 400` check on line 94 -- the first branch can never be reached without the second also being true. The `isSecurityRejection` check is dead code in the success path.

**Recommendation:** Replace `response.status >= 400` with `isInconclusive()` -> `skipped`, and keep `isSecurityRejection()` -> `passed: true`. Or, at minimum, exclude 401/429/5xx.

### Test 8: revocation-propagation

**Mostly correct but has a gap.**

```typescript
if (response.status === 200) {
    const body = response.body as Record<string, unknown>;
    if (body.active === false) { return { passed: true, ... }; }
    if (body.active === true) { return { passed: false, ... }; }
}
```

**Edge case:** If the AS returns HTTP 200 with an introspection body that does not contain `active` at all (or `active` is not a boolean), neither branch matches, and the function falls through to the `response.status >= 400` checks. Since `200 >= 400` is false, it falls to the final `return { skipped: true, ... }`. This is actually the correct behavior (inconclusive), but it happens for the wrong reason. A 200 response without `active` is a non-compliant introspection endpoint -- it might be worth calling out explicitly.

**Unsafe cast:** Line 69 casts `response.body as Record<string, unknown>`. If body is null or a string, `body.active` would throw or return undefined. Should use `jsonBody()`.

### Test 9: actor-client-mismatch

**Correct.** Uses the standard `isSecurityRejection -> isInconclusive -> fail` pattern.

### Test 10: delegation-impersonation-confusion

**Design concern: Security rejections are treated as "skipped," not "passed."**

```typescript
if (response.status !== 200) {
    if (isInconclusive(response)) {
        return { skipped: true, ... };
    }
    return { skipped: true, reason: `Exchange was rejected — ${describeResponse(response)}. Cannot verify act claim.` };
}
```

This test does not use `isSecurityRejection()`. A 400 `invalid_grant` returns `skipped: true`. This is **arguably correct** because this test is checking a different property (whether the `act` claim is present in successful exchanges), not whether the AS rejects malicious requests. If the AS rejects the exchange entirely, we cannot assess whether it would have included `act`. The `skipped` verdict is defensible.

However, the test never returns `passed: false` for non-200 responses. If the AS rejects a legitimate delegation exchange (agent-a exchanging with its own actor_token), that could indicate a configuration issue worth flagging, not just skipping.

### Test 11: scope-escalation

**Correct with a nuance.** The verify logic is the most sophisticated:

1. `isSecurityRejection` -> pass (AS rejected the scope request)
2. `isInconclusive` -> skip
3. HTTP 200 with constrained scope (no admin/write/delete) -> pass (AS downsized the scope)
4. HTTP 200 with escalated scope -> fail
5. HTTP 200 with no scope in response -> fail
6. Anything else -> fail

**Nuance:** Step 5 (`passed: false` when no scope in response) is correct-but-harsh. Per RFC 6749 Section 5.1, the AS MUST include the `scope` parameter in the response if the issued scope differs from the requested scope. If the AS returns 200 without `scope`, it could mean the AS granted exactly what was requested (escalated scope), which is indeed a failure. The logic is correct.

**Note on `invalid_scope`:** As mentioned above, this error code is not in `SECURITY_REJECTION_ERRORS` but works via the default-to-security-rejection fallback. Fragile but currently functional.

### Test 12: subject-actor-swap

**Correct.** Standard pattern. No issues.

---

## 3. Cross-Cutting Issues

### 3.1 The "unknown" Category Blind Spot

The `isInconclusive()` function returns true for `auth_error`, `rate_limit`, and `server_error`, but NOT for `"unknown"`. This means any status code not explicitly handled (302, 304, 404, 405, 408, 409, 413, 422, etc.) will:

1. Not be classified as `security_rejection` (correct)
2. Not be classified as `inconclusive` (debatable)
3. Fall through to the `passed: false` branch in most tests

**Result:** An AS that returns HTTP 404 (endpoint not found) or HTTP 405 (method not allowed) would be reported as "vulnerable" for every attack test. These are clearly misconfiguration issues, not security vulnerabilities.

**Recommendation:** Either add `"unknown"` to `isInconclusive()`, or introduce a new check like `isUnexpected()` that maps to `skipped`.

### 3.2 Inconsistent Use of classify.ts

| Test | Uses isSecurityRejection | Uses isInconclusive | Uses raw status checks | Risk Level |
|------|-------------------------|--------------------|-----------------------|------------|
| valid-delegation | No | No | Yes (`=== 200`) | Medium |
| basic-splice | Yes | Yes | No | Low |
| actor-client-mismatch | Yes | Yes | No | Low |
| aud-sub-binding | Yes | Yes | No | Low |
| upstream-splice | Yes | Yes | No | Low |
| subject-actor-swap | Yes | Yes | No | Low |
| multi-audience | Yes | Yes | No | Low |
| missing-aud | Yes | Yes | No | Low |
| may-act-enforcement | Yes (partial) | No | Yes (`>= 400`) | **High** |
| scope-escalation | Yes | Yes | Yes (`=== 200`) | Low |
| delegation-impersonation | No | Yes | Yes (`!== 200`) | Medium |
| refresh-bypass | Yes | No | Yes (`>= 400`) | **High** |
| revocation-propagation | No | No | Yes (multiple) | Medium |

The tests with `>= 400` raw status checks (may-act-enforcement, refresh-bypass) are the highest risk because they count infrastructure errors as security passes.

### 3.3 Unsafe Body Casts

Several tests cast `response.body as Record<string, unknown>` without first checking if the body is a non-null object. The `jsonBody()` helper in classify.ts exists specifically for this purpose but is not used in:

- `valid-delegation` (line 42)
- `revocation-propagation` (line 69)

If the AS returns a non-JSON body (plain text error, HTML error page, null), these casts could cause runtime errors or silent incorrect behavior.

---

## 4. Test Coverage Gaps in test-vectors.test.ts

### 4.1 Missing Edge Cases Per Test

| Test Vector | Security Rejection | Auth Error (401) | Success (200) | Rate Limit (429) | Server Error (500) | Unknown (302/404) | Notes |
|---|---|---|---|---|---|---|---|
| valid-delegation | Not applicable | **MISSING** | Tested | **MISSING** | **MISSING** | **MISSING** | Should test null body on 200 |
| basic-splice | Tested | Tested | Tested | Tested | **MISSING** | **MISSING** | Good coverage |
| actor-client-mismatch | Tested | Tested | Tested | **MISSING** | **MISSING** | **MISSING** | |
| aud-sub-binding | Tested | Tested | Tested | **MISSING** | **MISSING** | **MISSING** | |
| upstream-splice | Tested | **MISSING** | Tested | **MISSING** | Tested | **MISSING** | |
| subject-actor-swap | Tested | **MISSING** | Tested | **MISSING** | **MISSING** | **MISSING** | |
| multi-audience | Tested | **MISSING** | Tested | **MISSING** | **MISSING** | **MISSING** | |
| missing-aud | Tested | **MISSING** | Tested | **MISSING** | **MISSING** | **MISSING** | |
| may-act-enforcement | Tested | **MISSING** | Tested | **MISSING** | **MISSING** | **MISSING** | Critical gap given the bug |
| scope-escalation | Tested (invalid_scope) | **MISSING** | Tested (3 variants) | **MISSING** | **MISSING** | **MISSING** | |
| delegation-impersonation | Via 400 skip | **MISSING** | Tested (2 variants) | **MISSING** | **MISSING** | **MISSING** | Should test JWT with `act` claim |
| refresh-bypass | Tested | **MISSING** | Tested | **MISSING** | **MISSING** | Tested (302) | |
| revocation-propagation | Not applicable | Tested | Tested (2 variants) | **MISSING** | Tested | **MISSING** | |

### 4.2 Critical Missing Tests

1. **may-act-enforcement: No test for 401/429/500.** Given the `response.status >= 400` bug, tests for these inputs would have caught the false positive issue. A test like:
   ```typescript
   it("should NOT pass on 401 (auth error)", () => {
       const setup = { tokens: {}, metadata: { hasMayAct: true } };
       const verdict = mayActEnforcement.verify(makeResponse(401), setup);
       expect(verdict).not.toHaveProperty("passed", true);
   });
   ```
   **This test would FAIL with current code**, proving the bug.

2. **refresh-bypass: No test for 401/429/500.** Same issue as may-act-enforcement.

3. **valid-delegation: No test for null body on 200.** `makeResponse(200, null)` would cause a runtime error because `body.access_token` would throw on null.

4. **delegation-impersonation-confusion: No test with a real JWT containing `act` claim.** The test only checks opaque tokens and no-access_token responses. The "happy path" (JWT with `act` claim) is never tested.

5. **No test covers the `"unknown"` category (e.g., 302, 404) for any attack test vector.** refresh-bypass has a 302 test, but no other vector does.

### 4.3 Missing Negative Tests for classify.ts

- No test for `classifyResponse` with a non-standard error code on 400 (e.g., `error: "custom_error"`)
- No test for `classifyResponse` with array body
- No test for `classifyResponse` with string body
- No test for `extractErrorCode` with nested error objects (e.g., `error: { code: "invalid_grant" }`)

---

## 5. Severity-Ranked Findings

### HIGH Severity

| # | Finding | Test(s) Affected | Impact |
|---|---------|-----------------|--------|
| H1 | `may-act-enforcement` verify() counts 401/429/500 as pass (lines 74, 96) | may-act-enforcement | False positive: operator told AS enforces may_act when it actually returned auth/rate/server error |
| H2 | `refresh-bypass` verify() counts 401/429/500 as pass (line 94) | refresh-bypass | False positive: operator told refresh is delegation-aware when it actually returned auth/rate/server error |

### MEDIUM Severity

| # | Finding | Test(s) Affected | Impact |
|---|---------|-----------------|--------|
| M1 | `invalid_scope` missing from SECURITY_REJECTION_ERRORS | scope-escalation (and any future test) | Works by accident via default fallback; fragile |
| M2 | `valid-delegation` does not use jsonBody(), unsafe cast on null body | valid-delegation | Runtime crash if AS returns 200 with null/string body |
| M3 | `revocation-propagation` does not use jsonBody(), unsafe cast | revocation-propagation | Runtime crash if AS returns 200 with null/string body |

### LOW Severity

| # | Finding | Test(s) Affected | Impact |
|---|---------|-----------------|--------|
| L1 | `"unknown"` category (302/404/405) not in isInconclusive() | All attack tests | False negative for misconfigured endpoints |
| L2 | `unsupported_grant_type` not explicitly handled | All attack tests | AS that does not support token exchange at all would pass every splice test |
| L3 | `valid-delegation` does not distinguish infrastructure failure from security rejection | valid-delegation (baseline) | Confusing error messages for operators |
| L4 | `delegation-impersonation-confusion` never produces `passed: false` for non-200 | delegation-impersonation | Legitimate delegation rejections silently skipped |

---

## 6. Recommended Fixes

### Fix H1 and H2 (may-act-enforcement and refresh-bypass)

Replace the `response.status >= 400` checks with proper classification:

**may-act-enforcement (both hasMayAct branches):**
```typescript
// Replace:
if (response.status >= 400) {
    return { passed: true, reason: `AS rejected exchange — ${describeResponse(response)}` };
}

// With:
if (isInconclusive(response)) {
    return { skipped: true, reason: `Inconclusive: ${describeResponse(response)}` };
}
```

**refresh-bypass:**
```typescript
// Replace:
if (response.status >= 400) {
    return { passed: true, reason: `AS rejected refresh after upstream revocation — ${describeResponse(response)}` };
}

// With:
if (isInconclusive(response)) {
    return { skipped: true, reason: `Inconclusive: ${describeResponse(response)}` };
}
```

### Fix M1 (missing invalid_scope)

```typescript
const SECURITY_REJECTION_ERRORS = new Set([
    "invalid_grant",
    "invalid_target",
    "invalid_request",
    "invalid_scope",        // <-- add
    "unauthorized_client",
    "access_denied",
]);
```

### Fix M2 and M3 (unsafe body casts)

Replace `response.body as Record<string, unknown>` with `jsonBody(response)` and handle the `undefined` case.

### Fix L1 (unknown category)

Either add `"unknown"` to `isInconclusive()`, or add explicit handling in each verify() function:

```typescript
if (classifyResponse(response) === "unknown") {
    return {
        skipped: true,
        reason: `Unexpected response: ${describeResponse(response)} — cannot determine security posture`,
    };
}
```

---

## 7. Conclusion

The `classify.ts` abstraction is a well-designed safety net that prevents the most common false-positive pattern (treating all 4xx as security rejections). However, two tests (may-act-enforcement and refresh-bypass) bypass this safety net by using raw `response.status >= 400` checks, reintroducing the exact class of bugs that classify.ts was designed to prevent.

The highest-priority fixes are H1 and H2, which cause false positives -- the most dangerous failure mode for a security testing tool. An operator who receives "PASS: AS enforces may_act" when the AS actually returned a 500 server error has been given dangerously incorrect assurance.

Test coverage for verify() edge cases is moderate but has notable gaps, particularly around infrastructure failure modes (429, 500, 302) and the may-act/refresh tests that contain bugs. Adding the missing test cases would have caught both H1 and H2 bugs.
