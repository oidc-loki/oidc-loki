# splice-check Test Suite Legitimacy Audit

**Auditor:** Claude Opus 4.6 (automated)
**Date:** 2026-02-27
**Scope:** All test files in `tools/splice-check/tests/` and corresponding source files in `tools/splice-check/src/`

---

## Executive Summary

The test suite is generally well-structured and demonstrates genuine understanding of the OAuth 2.0 / RFC 8693 domain. The `test-vectors.test.ts` and `config.test.ts` files are the strongest -- they test real logic with meaningful assertions. However, the `runner.test.ts` has significant tautological issues because it mocks both input and output of the system under test. The `integration.test.ts` file is valuable but has mock fidelity problems that reduce its ability to detect real regressions. The `reporter.test.ts` relies heavily on substring matching, which is fragile but not meaningless.

**Issues found:** 27
- Critical: 5
- High: 10
- Medium: 12

---

## 1. `tests/runner.test.ts`

### 1.1 CRITICAL -- Tautological tests: `makeTest` bypasses all real logic

**Test names affected:** "runs all tests and returns results", "handles failing tests", "handles skipped tests"

**What's wrong:** The `makeTest()` helper on line 28 creates a test with hardcoded `setup`, `attack`, and `verify` functions that return static values. The runner is then tested against these fake tests. Since `verify` returns `{ passed: true, reason: "ok" }` by default, and the test asserts `summary.passed === 2`, the test is verifying that the runner can count hardcoded values -- not that any real verification logic works.

Specifically:
```ts
setup: async () => ({ tokens: {} }),
attack: async () => ({ status: 200, body: {}, headers: {}, durationMs: 1 }),
verify: () => ({ passed: true, reason: "ok" }),
```

The test `makeTest({ id: "test-1" }), makeTest({ id: "test-2" })` with assertion `expect(result.summary.passed).toBe(2)` is tautological -- the verify function is hardcoded to return passed:true, so the runner is just counting constants.

**How to fix:** This is actually acceptable for testing the **runner orchestration logic** (counting, filtering, callbacks). The tests should be clearly named to indicate they test the runner's orchestration, not the test logic. Add a comment clarifying that these tests validate the runner's lifecycle management, not attack verification. However, this is still a real gap -- there are no tests that validate the runner correctly wires `attack()` output into `verify()` input.

**Severity:** Critical -- the runner's core responsibility (wiring attack response into verify) is never tested. A bug where the runner passes the wrong response to verify() would not be caught.

---

### 1.2 HIGH -- "handles attack phase errors" uses fragile assertion pattern

**Line 122:**
```ts
expect(verdict && "passed" in verdict && !verdict.passed).toBe(true);
```

**What's wrong:** This expression is needlessly complex and could mask failures. If `verdict` is undefined, `verdict && "passed" in verdict && !verdict.passed` evaluates to `undefined`, and `expect(undefined).toBe(true)` fails -- so it's not vacuously true. However, if `verdict` has `{ skipped: true, ... }`, the expression `"passed" in verdict` is false, so the whole thing is `false`, and the test fails. This is testing the **type** of verdict, not just the value, which is good. But the assertion pattern is fragile and unclear -- if the runner changed to return `skipped` for attack errors (a reasonable change), this test would fail for the wrong reason.

**How to fix:** Use a more explicit assertion:
```ts
expect(verdict).toHaveProperty("passed", false);
expect(verdict).toHaveProperty("reason");
```

**Severity:** High -- the assertion obscures intent and would not produce a helpful error message on failure.

---

### 1.3 HIGH -- "handles setup failures gracefully" has same fragile assertion pattern

**Lines 105-106:**
```ts
expect(verdict && "skipped" in verdict && verdict.skipped).toBe(true);
expect(verdict && "reason" in verdict && verdict.reason).toContain("Setup failed");
```

**What's wrong:** Same pattern issue as 1.2. The second assertion is particularly fragile: `verdict && "reason" in verdict && verdict.reason` evaluates to the string value of `verdict.reason` if truthy, and `expect("Setup failed: Cannot connect to AS").toContain("Setup failed")` happens to work. But if the reason were an empty string, the expression evaluates to `""` (falsy), and `expect("").toContain(...)` would incorrectly fail.

**How to fix:**
```ts
expect(verdict).toHaveProperty("skipped", true);
expect(verdict).toHaveProperty("reason", expect.stringContaining("Setup failed"));
```

**Severity:** High

---

### 1.4 MEDIUM -- "tracks total duration" uses `.toBeGreaterThanOrEqual(0)`

**Line 188:**
```ts
expect(result.summary.durationMs).toBeGreaterThanOrEqual(0);
```

**What's wrong:** Overly permissive assertion. Duration 0 would pass, as would any positive number. This assertion would pass even if `durationMs` were always hardcoded to 0. It does not validate that timing is actually measured.

**How to fix:** Since the test runs at least one test with actual async work, assert `toBeGreaterThan(0)` or at minimum `toBeTypeOf("number")` plus `toBeGreaterThan(-1)`. Better: add a test with a known-delayed setup and assert duration is within a reasonable range.

**Severity:** Medium -- the assertion is nearly vacuous.

---

### 1.5 MEDIUM -- "includes test metadata in results" tests the `pick()` function but the assertion is hardcoded

**Lines 202-207:**
```ts
expect(result.results[0]?.test).toEqual({
    id: "meta-test",
    name: "Meta Test",
    severity: "critical",
    spec: "RFC 8693",
});
```

**What's wrong:** This tests that `pick()` correctly extracts fields from the test object, which is valid. However, the test passes `{ id: "meta-test", name: "Meta Test", severity: "critical", spec: "RFC 8693" }` in and asserts the exact same values come out. This is a tautology for the `pick()` function -- it would only fail if `pick()` were completely broken. It does not test that `description` is correctly excluded, for instance.

**How to fix:** Add `description: "Some description that should NOT appear in output"` to the makeTest call and assert the result does NOT contain a `description` field: `expect(result.results[0]?.test).not.toHaveProperty("description")`.

**Severity:** Medium

---

### 1.6 MEDIUM -- No test for concurrent test execution safety

**What's missing:** The runner processes tests sequentially in a `for` loop. There is no test verifying that shared state (like `knownTokens` in `runSingleTest`) does not leak between tests. If someone refactored to run tests in parallel, the test suite would not catch state leakage.

**How to fix:** Add a test with two tests where the second test's setup depends on NOT seeing the first test's tokens.

**Severity:** Medium

---

## 2. `tests/test-vectors.test.ts`

### 2.1 MEDIUM -- verify() tests bypass setup/attack entirely

**What's wrong:** All verify tests (lines 168-433) call `verify(makeResponse(...), emptySetup)` directly, bypassing the `setup()` and `attack()` phases. This is correct for unit-testing the judgment logic, but `emptySetup` (`{ tokens: {} }`) is not representative of real usage -- in production, `setup` populates `tokens` and `metadata` that `verify()` may depend on.

For most tests this is fine because their verify functions only use `response`. But for tests like `multi-audience`, `missing-aud`, and `may-act-enforcement` that read `setup.metadata`, the test does pass correct metadata (e.g., `{ hasMultiAud: true }`). This is good.

However, there is a subtle gap: `emptySetup` has `tokens: {}` but verify functions never use `setup.tokens`. If a future verify function were to check tokens (e.g., comparing the response token with the setup token), these tests would silently pass with empty tokens.

**How to fix:** Use more realistic setup objects that include tokens. For current verify functions, this is low priority.

**Severity:** Medium -- acceptable for unit tests of judgment logic, but the gap should be documented.

---

### 2.2 HIGH -- `delegation-impersonation-confusion` verify test does not cover the JWT `act` claim path

**Lines 376-394:**

The test covers three paths:
1. Exchange rejected (400) -> skipped
2. 200 with no access_token -> failed
3. Opaque token ("opaque-not-jwt") -> skipped

**What's missing:** The actual positive case -- a JWT access token WITH an `act` claim that should result in `passed: true`. And the critical negative case -- a JWT WITHOUT an `act` claim that should result in `passed: false`. The source code (delegation-impersonation-confusion.ts lines 81-106) uses `decodeJwt` from `jose` to inspect the token. Neither the positive nor negative JWT path is tested.

**How to fix:** Create a test with a real (unsigned) JWT as the access_token that contains an `act` claim, and another without:
```ts
// JWT with act claim (base64url encoded)
const jwtWithAct = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSIsImFjdCI6eyJzdWIiOiJhZ2VudC1hIn19.";
// JWT without act claim
const jwtWithoutAct = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9.";
```

**Severity:** High -- the core security assertion of this test (checking for `act` claim) is completely untested at the unit level.

---

### 2.3 HIGH -- `refresh-bypass` verify has no test for the `status >= 400` non-security-rejection path

**Lines 396-411:**

The verify function in `refresh-bypass.ts` has a code path at line 94:
```ts
if (response.status >= 400) {
    return { passed: true, reason: ... };
}
```
This covers cases where the AS rejects the refresh with a non-standard error code (not in the security_rejection set). Only the `isSecurityRejection` path (400 with `invalid_grant`) and the 200 success path are tested. The generic 400-without-recognized-error-code path and the non-standard error status paths (e.g., 422, 503) are not tested.

**How to fix:** Add test cases for `makeResponse(422)` and `makeResponse(400, { error: "server_error" })` to verify these also pass.

Wait -- actually, looking more carefully at the source code, `isSecurityRejection(makeResponse(400, { error: "invalid_grant" }))` is true, which makes the first `if` branch match. But `isSecurityRejection` also matches 400 with no error code (returns "security_rejection" from classify). So `makeResponse(400)` without a body would also hit the first branch. The line-94 branch `if (response.status >= 400)` is only reachable when `isSecurityRejection` returns false AND the status is >= 400 -- this happens for 401, 429, 500 etc. But wait, those are preceded by `isSecurityRejection` which returns false for them, and they are NOT "inconclusive" in the refresh-bypass verify because there is no `isInconclusive` check. So 401, 429, 500 all fall through to `status >= 400` check and return passed: true.

This means a 429 rate limit would be treated as "passed" -- the refresh was rejected. But this is potentially wrong -- the refresh was rate-limited, not security-rejected.

**How to fix:** Add test cases for 401, 429, 500 and consider whether these should be "passed" or "skipped/inconclusive" in the verify logic.

**Severity:** High -- potential false positives in the source logic, and the test suite does not exercise these paths.

---

### 2.4 HIGH -- `revocation-propagation` verify is missing the 403 path

**Lines 413-433:**

The source code at `revocation-propagation.ts` line 87 has:
```ts
if (response.status === 401 || response.status === 403) {
    return { skipped: true, ... };
}
```

The test covers:
- 200 with `active: false` (passed)
- 200 with `active: true` (failed)
- 401 (skipped)
- 500 (skipped)

Missing: **403** is not tested. The source code explicitly handles it but the test does not verify that behavior.

**How to fix:** Add:
```ts
it("skips when introspection returns 403", () => {
    const verdict = revocationPropagation.verify(makeResponse(403), emptySetup);
    expect(verdict).toHaveProperty("skipped", true);
});
```

**Severity:** High -- explicit code path not tested.

---

### 2.5 MEDIUM -- `scope-escalation` test for "constrains scope" is hardcoded to specific scope strings

**Lines 354-360:**

```ts
const verdict = scopeEscalation.verify(
    makeResponse(200, { access_token: "tok", scope: "openid profile" }),
    emptySetup,
);
expect(verdict).toHaveProperty("passed", true);
```

**What's wrong:** The verify logic checks `grantedScopes.has("admin") || grantedScopes.has("write") || grantedScopes.has("delete")`. The test only verifies the path where NONE of those are present. It would be stronger to also test edge cases: `scope: "admin"` alone, `scope: "readonly write"`, `scope: ""`.

**How to fix:** Add edge case assertions for scopes containing only one escalated term, empty scope string, etc.

**Severity:** Medium

---

### 2.6 MEDIUM -- `missing-aud` and `multi-audience` tests never verify the `isInconclusive` path

Both `missing-aud` and `multi-audience` source files contain `isInconclusive` branches that return `skipped`. Neither test file exercises these paths (e.g., what happens when the response is 401 or 429).

**How to fix:** Add for each:
```ts
it("skips on inconclusive response (401)", () => {
    const setup: SetupResult = { tokens: {}, metadata: { hasAud: false } };
    const verdict = missingAud.verify(makeResponse(401), setup);
    expect(verdict).toHaveProperty("skipped", true);
});
```

**Severity:** Medium -- missing negative path coverage.

---

### 2.7 MEDIUM -- `subject-actor-swap` does not test inconclusive paths

The test at lines 266-276 covers passed (400) and failed (200) but does not test the `isInconclusive` branch for 401, 429, or 500.

**How to fix:** Add:
```ts
it("skips on inconclusive (429)", () => {
    const verdict = subjectActorSwap.verify(makeResponse(429), emptySetup);
    expect(verdict).toHaveProperty("skipped", true);
});
```

**Severity:** Medium

---

## 3. `tests/client.test.ts`

### 3.1 HIGH -- Mock AS is too simplistic: cross-chain splice detection is based on string matching, not JWT validation

**Lines 62-68:**

```ts
if (subjectToken?.includes("alice") && actorToken?.includes("agent-n")) {
    res.writeHead(400);
    // ...
}
```

**What's wrong:** The mock AS detects cross-chain splicing by checking if the subject_token string contains "alice" and the actor_token string contains "agent-n". A real AS would decode the JWTs, validate signatures, and compare `sub`/`aud` claims. This means the client test for "returns 400 for cross-chain splice attempt" (line 160) only validates that the HTTP client correctly transmits the request and parses the response -- it does NOT validate that the client correctly constructs the token exchange request in a way that a real AS could evaluate.

This is acceptable for a client unit test (testing HTTP mechanics), but should be clearly documented. The mock fidelity issue becomes a problem if someone reads this test and assumes it validates security behavior.

**How to fix:** Add a comment to the mock AS: `// Simplified detection for client HTTP testing -- does not represent real AS validation logic`. Or better: in the mock, parse the token content rather than using string matching.

**Severity:** High -- mock fidelity issue that could give false confidence.

---

### 3.2 MEDIUM -- `refreshToken` test does not verify the correct refresh_token is sent

**Lines 210-216:**

```ts
it("refreshes a token", async () => {
    const client = new OAuthClient(makeTarget(baseUrl), testClients);
    const response = await client.refreshToken("refresh-token-123", "agent-a");
    expect(response.status).toBe(200);
    expect((response.body as Record<string, unknown>).access_token).toBe("refreshed-token");
});
```

**What's wrong:** The test verifies the response is 200 with a refreshed token, but does not verify that the correct refresh_token value ("refresh-token-123") was actually sent in the request body. The mock AS does not validate the refresh_token parameter at all -- it returns 200 for ANY refresh_token request. The test could pass even if the client sent the wrong token or no token.

**How to fix:** Capture the request body in the `requests` array (already available) and assert:
```ts
const lastRequest = requests[requests.length - 1];
const params = new URLSearchParams(lastRequest?.body);
expect(params.get("refresh_token")).toBe("refresh-token-123");
```

**Severity:** Medium -- the test does not verify the actual data sent to the server.

---

### 3.3 MEDIUM -- `revokeToken` test does not verify the token or token_type_hint are sent

**Lines 219-223:**

```ts
it("revokes a token", async () => {
    const response = await client.revokeToken("some-token", "alice", "access_token");
    expect(response.status).toBe(200);
});
```

**What's wrong:** Only checks status 200. Does not verify:
- The `token` parameter was sent with value "some-token"
- The `token_type_hint` parameter was sent with value "access_token"
- The correct endpoint was hit (`/oauth2/revoke`)

**How to fix:** Inspect `requests` array:
```ts
requests.length = 0;
await client.revokeToken("some-token", "alice", "access_token");
const lastReq = requests[requests.length - 1];
expect(lastReq?.path).toBe("/oauth2/revoke");
const params = new URLSearchParams(lastReq?.body);
expect(params.get("token")).toBe("some-token");
expect(params.get("token_type_hint")).toBe("access_token");
```

**Severity:** Medium -- important parameters are not verified.

---

### 3.4 MEDIUM -- `introspectToken` tests do not verify the correct endpoint is hit

**Lines 227-239:**

Tests verify the response body but not that the request went to `/oauth2/introspect` or that the correct `token` parameter was sent.

**How to fix:** Same approach as 3.3 -- inspect the `requests` array.

**Severity:** Medium

---

### 3.5 MEDIUM -- No test for `revokeToken` without `tokenTypeHint`

The `revokeToken` method has an optional `tokenTypeHint` parameter. Only the case where it IS provided is tested. The case where it is omitted (which should NOT include `token_type_hint` in the request body) is not tested.

**How to fix:** Add:
```ts
it("revokes a token without token_type_hint", async () => {
    requests.length = 0;
    await client.revokeToken("some-token", "alice");
    const params = new URLSearchParams(requests[requests.length - 1]?.body);
    expect(params.has("token_type_hint")).toBe(false);
});
```

**Severity:** Medium

---

### 3.6 MEDIUM -- No test for `tokenExchange` with `resource` parameter

The `TokenExchangeParams` type includes `resource?: string | string[]` and the client has `appendMultiValue` logic for it. No test exercises the `resource` parameter at all.

**How to fix:** Add a test that passes `resource: "https://api.example.com"` and verifies it appears in the request body. Also test multi-valued: `resource: ["https://api1.example.com", "https://api2.example.com"]`.

**Severity:** Medium -- untested code path in the client.

---

### 3.7 HIGH -- No test for timeout behavior

The `OAuthClient` uses `AbortSignal.timeout(timeout)` (line 180 of client.ts), with a configurable `target.timeout`. No test verifies:
- The default timeout (30000ms) is applied
- A custom timeout from config is respected
- Timeout errors are properly propagated

**How to fix:** Create a mock server that delays response beyond the timeout, configure a short timeout, and verify the error.

**Severity:** High -- timeout handling is critical for a security testing tool that hits live servers.

---

## 4. `tests/config.test.ts`

### 4.1 MEDIUM -- Environment variable cleanup uses assignment instead of delete

**Line 278:**
```ts
process.env.TEST_SC_SECRET = undefined;
```

**What's wrong:** Assigning `undefined` to `process.env` actually sets the value to the string `"undefined"`, not removes it. The correct cleanup is:
```ts
delete process.env.TEST_SC_SECRET;
```

This could cause test pollution if `loadConfig` is later called in the same test run and encounters `TEST_SC_SECRET` with value `"undefined"`.

**How to fix:** Change to `delete process.env.TEST_SC_SECRET;`

**Severity:** Medium -- potential test pollution.

---

### 4.2 MEDIUM -- No test for malformed TOML

There is a test for nonexistent file but no test for a file containing syntactically invalid TOML (e.g., missing quotes, bad syntax). The `parse()` function from `smol-toml` would throw, and it's worth verifying the error surfaces correctly.

**How to fix:** Add:
```ts
it("throws on malformed TOML", () => {
    const path = writeToml("bad.toml", "[target\ntoken_endpoint = ");
    expect(() => loadConfig(path)).toThrow();
});
```

**Severity:** Medium

---

### 4.3 LOW (no issue) -- Config tests are well-structured

The config tests are the strongest in the suite. They test:
- Valid config loading with full field verification
- Default values for auth method and output format
- Missing required sections and fields
- Invalid enum values
- Environment variable interpolation (both success and failure)
- Optional fields
- All required clients checked

This is a well-done test file with no tautological issues.

---

## 5. `tests/reporter.test.ts`

### 5.1 HIGH -- Tests use fixture data that never flows through the system under test

**Lines 9-78:**

The `passResult` and `mixedResult` fixtures are manually constructed `RunResult` objects. They are never produced by the actual `runTests()` function. This means:
- If the `RunResult` type changes shape, the fixtures may become stale
- If `formatResults` assumes invariants that `runTests` guarantees (e.g., that durations are always non-negative, that there's always a summary), the tests wouldn't catch violations

**How to fix:** Either generate fixtures through `runTests()` or add a compile-time type check (the TypeScript typing already handles this to some extent). This is acceptable for reporter unit tests but worth noting.

**Severity:** Medium -- acceptable for reporter testing, but fixtures could drift from reality.

---

### 5.2 HIGH -- JSON format test uses `.toBeDefined()` for parsed results

**Line 118:**
```ts
expect(parsed).toBeDefined();
```

**What's wrong:** Overly permissive assertion. `JSON.parse()` would throw on invalid JSON before reaching this assertion, so `.toBeDefined()` is vacuously true -- if `JSON.parse` succeeded, the result is always defined. This assertion adds no value.

**How to fix:** Remove the `.toBeDefined()` check (the `JSON.parse` call implicitly validates JSON) or replace with a structural assertion:
```ts
expect(parsed).toHaveProperty("results");
expect(parsed).toHaveProperty("summary");
```
(The test already does `expect(parsed.results).toHaveLength(2)` on the next line, which implicitly validates `parsed` is defined.)

**Severity:** High -- vacuously true assertion.

---

### 5.3 MEDIUM -- Table format tests rely on substring matching

**Lines 87-111:**

All table format tests use `expect(output).toContain("PASS")` style assertions. These are fragile because:
- "PASS" could appear in other contexts (e.g., a test name containing "PASS")
- The assertions don't validate structure or ordering

**How to fix:** Use snapshot testing or more precise patterns:
```ts
expect(output).toMatch(/\+.*valid-delegation.*PASS/);
expect(output).toMatch(/!.*basic-splice.*FAIL/);
```

**Severity:** Medium -- tests are meaningful but could false-positive.

---

### 5.4 MEDIUM -- No test for table format with verbose logs

The `formatTable` function does not appear to render logs, but this is not verified. If someone adds log rendering to the table format, there's no test to validate it.

**How to fix:** Add a test with non-empty logs and verify they are or aren't included in table output.

**Severity:** Medium

---

### 5.5 MEDIUM -- JSON format "excludes logs when empty" tests an implementation detail

**Lines 140-144:**
```ts
it("excludes logs when empty", () => {
    const parsed = JSON.parse(formatResults(passResult, "json"));
    expect(parsed.results[0].logs).toBeUndefined();
});
```

**What's wrong:** This tests that empty log arrays are serialized as `undefined` (omitted) rather than `[]`. This is an implementation detail of the JSON serializer, not a correctness requirement. The source at reporter.ts line 82 has `logs: r.logs.length > 0 ? r.logs : undefined`, which deliberately omits empty logs. The test validates this behavior but it's not a correctness concern.

Not a real issue, just noting it's a low-value test.

**Severity:** Medium (low-value test, not incorrect)

---

## 6. `tests/integration.test.ts`

### 6.1 CRITICAL -- Vulnerable AS mock accepts ALL exchanges unconditionally

**Lines 46-55:**

```ts
} else if (grantType === "urn:ietf:params:oauth:grant-type:token-exchange") {
    // Vulnerable: accepts ALL exchanges without validation
    res.writeHead(200);
    res.end(JSON.stringify({
        access_token: `exchanged-${Date.now()}`,
        ...
    }));
}
```

**What's wrong:** The "vulnerable" AS always returns a `scope`-less 200 for exchanges. This means:
- `scope-escalation` test: The verify function checks `body?.scope` and finds it undefined, returning `passed: false` with reason "no scope in response". This IS the correct behavior for a vulnerable AS (failing the test = detecting vulnerability).
- `delegation-impersonation-confusion` test: The access_token is `exchanged-${Date.now()}` which is not a JWT. The verify function will catch the `decodeJwt` failure and return `skipped`. This means the delegation-impersonation test is **always skipped** against the vulnerable AS -- the vulnerability cannot be detected.

The mock is not wrong per se, but the integration test on line 207 asserts `expect(result.summary.failed).toBeGreaterThan(0)` which would pass as long as ANY test fails. It does not assert WHICH tests fail or WHICH are skipped. A regression where a test switches from "fail" to "skip" would go unnoticed.

**How to fix:** Assert specific test outcomes:
```ts
const basicSplice = result.results.find(r => r.test.id === "basic-splice");
expect(basicSplice?.verdict).toHaveProperty("passed", false);
```

**Severity:** Critical -- the integration test cannot detect if individual test behaviors regress.

---

### 6.2 CRITICAL -- Secure AS mock uses naive string matching for security decisions

**Lines 94-95:**

```ts
if (actorToken && !subjectToken.includes(clientId)) {
    res.writeHead(400);
```

**What's wrong:** The secure AS's "security" check is: does the subject_token string contain the client_id of the requesting client? Since tokens are of the form `token-{clientId}`, this works for the mock's own tokens. But:

1. The check `!subjectToken.includes(clientId)` means if `clientId` is "agent-a" and subjectToken is "token-agent-a", it passes. But `token-agent-a-extended` would also pass, which is unrealistic.

2. More critically: the `valid-delegation` test does exchange without `actor_token`, so the `actorToken && ...` check is false, and the exchange succeeds. This is correct. But the `basic-splice` test presents alice's token as subject with agent-n as actor and clientName "agent-n". The subject_token would be `token-alice-app` (from client_credentials for alice). `clientId` is "agent-n". `"token-alice-app".includes("agent-n")` is false, so the AS rejects. This is the correct behavior.

But for `upstream-splice`, the setup performs: alice -> agent-a exchange (succeeds, returns `exchanged-agent-a`), then agent-n tries to use `exchanged-agent-a` as subject with its own token as actor. Subject is "exchanged-agent-a", clientId is "agent-n". `"exchanged-agent-a".includes("agent-n")` is false, so AS rejects. Correct.

For `subject-actor-swap`: agent-n's token as subject (`token-agent-n`), alice's as actor, clientName "agent-n". `"token-agent-n".includes("agent-n")` is TRUE, so AS accepts the exchange even though it's a swap attack. This means the secure AS is **vulnerable to subject-actor-swap** in the mock, which would cause that test to fail (detecting the attack). But the secure AS is supposed to be... secure.

**The secure mock does not actually implement secure behavior for all attacks.** Tests against the secure AS only check `valid-delegation` and `basic-splice` (lines 218-242), so this gap is not surfaced. But it means the integration test gives false confidence that "secure AS" is actually secure.

**How to fix:** Either:
1. Make the secure AS actually implement all relevant security checks, or
2. Only claim it's "secure against basic splice" and test accordingly, or
3. Add integration tests for all 13 tests against the secure AS and document expected outcomes.

**Severity:** Critical -- the "secure AS" is not actually secure, undermining the integration test's value.

---

### 6.3 HIGH -- "runs all tests and finds failures" uses `.toBeGreaterThan(0)`

**Line 213:**
```ts
expect(result.summary.failed).toBeGreaterThan(0);
```

**What's wrong:** Overly permissive. This test runs all 13 tests against the vulnerable AS but only asserts "at least one test failed." It does not assert:
- Which tests failed (expected: basic-splice, actor-client-mismatch, etc.)
- Which tests passed (expected: valid-delegation should pass)
- The total number of failures

A regression that changes 10 failures to 1 failure would still pass this test.

**How to fix:** Assert specific counts or specific test outcomes:
```ts
expect(result.summary.passed).toBeGreaterThanOrEqual(1); // At least valid-delegation
expect(result.summary.failed).toBeGreaterThanOrEqual(3); // At least the core splice attacks
// Or better, check specific test IDs
```

**Severity:** High -- the assertion is too weak to catch regressions.

---

### 6.4 HIGH -- Vulnerable AS does not implement revocation or introspection endpoints

The `createVulnerableAS` function (lines 25-66) only handles:
- `client_credentials`
- `token-exchange`
- `refresh_token`
- unsupported_grant_type

It does not handle `/oauth2/revoke` or `/oauth2/introspect`. Tests that depend on these endpoints (`revocation-propagation`, `refresh-bypass`) will get 404 responses from the vulnerable AS. The 404 will be treated as:
- `refresh-bypass`: 404 is not `isSecurityRejection` and not `status >= 400`... wait, 404 IS >= 400, so it returns `passed: true`. This means refresh-bypass PASSES against the vulnerable AS. But the vulnerable AS does NOT actually validate revocation -- it just doesn't have a revocation endpoint. This is a false positive.
- `revocation-propagation`: The setup's attack phase calls `revokeToken` (which hits /oauth2/revoke -> 404) and then `introspectToken` (which hits /oauth2/introspect -> 404). The verify function sees 404 and returns `skipped`.

Wait, looking more carefully: the vulnerable AS mock doesn't even have URL routing. All requests go through the same handler. The `req.url` is not checked -- all requests are dispatched based on `grant_type` in the body. So `/oauth2/revoke` with `token` in the body (no `grant_type`) would hit the `else` branch at line 62 and return 400 with `unsupported_grant_type`. Similarly for introspect.

Actually, for `revokeToken`, the client sends `token=...` (and optionally `token_type_hint=...`) but NOT `grant_type`. The URLSearchParams would have `grant_type` as null. The mock checks `grantType === "client_credentials"`, etc. -- none match, so it falls through to the `else` at line 62: `res.writeHead(400)` with `unsupported_grant_type`. So revocation returns 400 (not 200 as expected by RFC 7009).

For `refresh-bypass`: setup calls `tokenExchange` (succeeds, gets `refresh_token` from line 54), then `revokeToken` (returns 400 -- but the attack phase still continues), then `refreshToken` (succeeds, returns 200 with `refreshed-${Date.now()}`). The verify sees 200 with `access_token` and correctly returns `passed: false` (bypass detected).

Actually wait -- the setup for `refresh-bypass` calls `revokeToken` in the attack phase, not setup. Let me re-read. The setup gets alice's token, exchanges it, and captures the refresh_token. The attack phase: (1) revokes alice's token (returns 400 from the vulnerable AS due to no revocation endpoint), then (2) refreshes with the refresh_token (returns 200). The verify sees 200 and returns `passed: false`. So the test correctly detects that the vulnerable AS doesn't properly handle revocation.

But the *reason* is misleading -- the AS didn't fail to re-validate delegation context; it simply doesn't have a revocation endpoint. The test result is correct (vulnerable) but for the wrong reason.

**How to fix:** Add revocation and introspection handlers to the vulnerable AS mock, with vulnerable behavior (accepting everything).

**Severity:** High -- mock fidelity issue.

---

### 6.5 MEDIUM -- Secure AS mock always returns `active: false` for introspection

**Line 124:**
```ts
} else if (req.url === "/oauth2/introspect") {
    res.writeHead(200);
    res.end(JSON.stringify({ active: false }));
}
```

**What's wrong:** The secure AS unconditionally returns `active: false` for ALL introspection requests. This means `revocation-propagation` would always pass (downstream token appears inactive) regardless of whether revocation actually propagated. A real secure AS would only return `active: false` for tokens that were actually revoked.

**How to fix:** Track revoked tokens in the mock and return `active: true` for non-revoked tokens, `active: false` for revoked ones.

**Severity:** Medium -- mock too simple to test real behavior, but the test correctly exercises the happy path.

---

### 6.6 MEDIUM -- No test for the `bailOnBaselineFailure` integration path

The runner supports `bailOnBaselineFailure` and it's tested in `runner.test.ts` with mock tests. But the integration test never exercises this with real AS responses. If the secure AS's valid-delegation happened to fail, all other tests should be skipped -- this is never validated end-to-end.

**How to fix:** Add an integration test with a misconfigured AS (e.g., wrong client credentials) that causes baseline failure.

**Severity:** Medium

---

### 6.7 MEDIUM -- No test validates that `allTests.slice(0, 1)` is actually `valid-delegation`

**Line 189:**
```ts
const result = await runTests(allTests.slice(0, 1), config, client);
```

**What's wrong:** This assumes `allTests[0]` is `valid-delegation`. If the array order in `index.ts` changes, this test would silently test a different test vector. The test should use `allTests.filter(t => t.id === "valid-delegation")` (as is done on line 221) for consistency and safety.

**How to fix:** Replace `allTests.slice(0, 1)` with `allTests.filter(t => t.id === "valid-delegation")`.

**Severity:** Medium -- fragile assumption about array order.

---

## 7. Cross-Cutting Issues

### 7.1 CRITICAL -- No test verifies that setup() output is correctly wired to attack() and verify()

Across all test files, there is no test that validates the full lifecycle: setup produces tokens -> attack uses those tokens -> verify evaluates the response in context of setup. The runner test uses mocks for all three phases. The integration test runs the full lifecycle but only checks final verdicts, not that intermediate data flows correctly.

If the runner had a bug where it passed a stale `SetupResult` to `verify()` (e.g., from a previous test), no test would catch it.

**How to fix:** Add a targeted integration test or runner test that:
1. Creates a test where `setup()` returns specific tokens
2. The `attack()` function asserts it receives those exact tokens
3. The `verify()` function asserts it receives the correct setup result

**Severity:** Critical -- fundamental data flow is untested.

---

### 7.2 HIGH -- No test for network error handling in integration tests

The integration tests use `localhost` mock servers. There are no tests for:
- Connection refused (server not running)
- DNS resolution failure
- TLS errors
- Malformed responses (e.g., non-JSON content-type with JSON body)

These are all real scenarios when testing live Authorization Servers.

**How to fix:** Add tests with a mock server that returns malformed responses, or test against a non-listening port.

**Severity:** High -- critical for a security testing tool.

---

### 7.3 HIGH -- `may-act-enforcement` verify has a logic flaw that tests don't catch

In `may-act-enforcement.ts` lines 67-86:
```ts
if (!hasMayAct) {
    if (isSecurityRejection(response)) {
        return { passed: true, ... };
    }
    if (response.status >= 400) {
        return { passed: true, ... };
    }
    return { skipped: true, ... };
}
```

When `hasMayAct` is false and response status >= 400 (but not a security rejection -- e.g., 401 auth error), the test returns `passed: true`. This is incorrect: a 401 auth error when may_act is not present should be `skipped` (inconclusive), not `passed`. The test at line 332:
```ts
it("passes when may_act not present but AS still rejects", () => {
    const setup: SetupResult = { tokens: {}, metadata: { hasMayAct: false } };
    const verdict = mayActEnforcement.verify(makeResponse(400), setup);
    expect(verdict).toHaveProperty("passed", true);
});
```
This confirms the behavior but doesn't test the potentially buggy case of 401 with `hasMayAct: false`.

**How to fix:** Add:
```ts
it("handles 401 when may_act not present", () => {
    const setup: SetupResult = { tokens: {}, metadata: { hasMayAct: false } };
    const verdict = mayActEnforcement.verify(makeResponse(401), setup);
    // Should this be skipped (auth error) or passed (rejection)?
    // Current code returns passed:true, which is arguably wrong
});
```

**Severity:** High -- potential logic bug in production code that the test suite confirms rather than catches.

---

## Summary Table

| # | File | Test/Area | Issue Type | Severity |
|---|------|-----------|-----------|----------|
| 1.1 | runner.test.ts | makeTest tautology | Tautological test | Critical |
| 1.2 | runner.test.ts | attack error assertion | Fragile assertion | High |
| 1.3 | runner.test.ts | setup failure assertion | Fragile assertion | High |
| 1.4 | runner.test.ts | duration check | Overly permissive | Medium |
| 1.5 | runner.test.ts | metadata test | Weak assertion | Medium |
| 1.6 | runner.test.ts | concurrency safety | Missing test | Medium |
| 2.1 | test-vectors.test.ts | emptySetup usage | Mock fidelity | Medium |
| 2.2 | test-vectors.test.ts | delegation-impersonation JWT paths | Missing negative case | High |
| 2.3 | test-vectors.test.ts | refresh-bypass status>=400 path | Missing path coverage | High |
| 2.4 | test-vectors.test.ts | revocation-propagation 403 | Missing path coverage | High |
| 2.5 | test-vectors.test.ts | scope-escalation edge cases | Missing edge cases | Medium |
| 2.6 | test-vectors.test.ts | missing-aud/multi-audience inconclusive | Missing negative case | Medium |
| 2.7 | test-vectors.test.ts | subject-actor-swap inconclusive | Missing negative case | Medium |
| 3.1 | client.test.ts | Mock AS string matching | Mock fidelity | High |
| 3.2 | client.test.ts | refreshToken request body | Missing assertion | Medium |
| 3.3 | client.test.ts | revokeToken request params | Missing assertion | Medium |
| 3.4 | client.test.ts | introspectToken endpoint | Missing assertion | Medium |
| 3.5 | client.test.ts | revokeToken without hint | Missing negative case | Medium |
| 3.6 | client.test.ts | resource parameter | Missing coverage | Medium |
| 3.7 | client.test.ts | timeout handling | Missing test | High |
| 4.1 | config.test.ts | env var cleanup | Test pollution | Medium |
| 4.2 | config.test.ts | malformed TOML | Missing negative case | Medium |
| 5.1 | reporter.test.ts | Fixture data | Mock fidelity | Medium |
| 5.2 | reporter.test.ts | toBeDefined vacuous | Vacuously true | High |
| 5.3 | reporter.test.ts | Substring matching | Fragile assertions | Medium |
| 6.1 | integration.test.ts | Vulnerable AS accepts all | Mock fidelity | Critical |
| 6.2 | integration.test.ts | Secure AS string matching | Mock fidelity | Critical |
| 6.3 | integration.test.ts | .toBeGreaterThan(0) | Overly permissive | High |
| 6.4 | integration.test.ts | Missing revoke/introspect | Mock fidelity | High |
| 6.5 | integration.test.ts | Secure AS introspection | Mock fidelity | Medium |
| 6.6 | integration.test.ts | bailOnBaselineFailure E2E | Missing test | Medium |
| 6.7 | integration.test.ts | allTests.slice(0,1) | Fragile assumption | Medium |
| 7.1 | cross-cutting | Setup->Attack->Verify wiring | Data flow untested | Critical |
| 7.2 | cross-cutting | Network error handling | Missing test | High |
| 7.3 | cross-cutting | may-act-enforcement logic | Test confirms bug | High |

---

## Priority Recommendations

### Immediate (Critical)

1. **Add a data flow integration test** (7.1) that verifies setup output flows correctly through attack and verify phases.
2. **Strengthen integration test assertions** (6.1, 6.3) to assert specific test outcomes, not just "at least one failure."
3. **Fix the secure AS mock** (6.2) to actually implement security checks, or clearly document its limitations.

### Short-term (High)

4. **Add JWT path tests** for delegation-impersonation-confusion (2.2).
5. **Add missing path coverage** for refresh-bypass (2.3), revocation-propagation (2.4).
6. **Add timeout tests** for OAuthClient (3.7).
7. **Add network error tests** (7.2).
8. **Review may-act-enforcement verify logic** (7.3) for correctness.
9. **Add revocation/introspection to vulnerable AS mock** (6.4).

### Medium-term (Medium)

10. Fix env var cleanup in config tests (4.1).
11. Add request body assertions to client tests (3.2, 3.3, 3.4).
12. Add inconclusive path tests for all verify functions (2.6, 2.7).
13. Replace `allTests.slice(0,1)` with explicit filter (6.7).
