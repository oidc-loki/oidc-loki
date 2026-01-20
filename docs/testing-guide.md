# Testing Guide

This guide explains how to use OIDC-Loki to test your OIDC client implementations for security vulnerabilities.

## Philosophy

OIDC-Loki follows a "chaos engineering" approach to security testing:

1. **Hypothesis**: Your OIDC client should reject malformed tokens
2. **Experiment**: Loki produces specific malformed tokens
3. **Verify**: Your client either correctly rejects them or fails
4. **Learn**: The ledger tells you exactly what was tested

## Test Structure

### Basic Pattern

```typescript
import { Loki } from "oidc-loki";
import { describe, it, beforeAll, afterAll, expect } from "vitest";

describe("OIDC Client Security Tests", () => {
  let loki: Loki;
  const PORT = 9000;
  const ISSUER = `http://localhost:${PORT}`;

  beforeAll(async () => {
    loki = new Loki({
      server: { port: PORT, host: "localhost" },
      provider: {
        issuer: ISSUER,
        clients: [
          {
            client_id: "test-app",
            client_secret: "test-secret",
            grant_types: ["client_credentials"],
          },
        ],
      },
      persistence: { enabled: false, path: "" },
    });
    await loki.start();
  });

  afterAll(async () => {
    await loki.stop();
  });

  // Tests go here
});
```

### Getting a Malicious Token

```typescript
async function getMaliciousToken(sessionId: string): Promise<string> {
  const response = await fetch(`${ISSUER}/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${btoa("test-app:test-secret")}`,
      "X-Loki-Session": sessionId, // Critical: links to mischief session
    },
    body: "grant_type=client_credentials",
  });

  const { access_token } = await response.json();
  return access_token;
}
```

## Attack Scenarios

### 1. Algorithm None Attack (CVE-2015-9235)

Tests if your client accepts unsigned tokens with `alg: "none"`.

```typescript
it("should reject tokens with alg:none", async () => {
  const session = loki.createSession({
    name: "alg-none-test",
    mode: "explicit",
    mischief: ["alg-none"],
  });

  const token = await getMaliciousToken(session.id);

  // Verify Loki applied the attack
  const [header] = token.split(".");
  const decoded = JSON.parse(atob(header));
  expect(decoded.alg).toBe("none");

  // YOUR TEST: Verify your client rejects it
  await expect(yourClient.validateToken(token)).rejects.toThrow();
});
```

**What this tests:**
- RFC 8725 Section 3.1 compliance
- CWE-327: Use of broken cryptographic algorithm

### 2. Key Confusion Attack (CVE-2016-10555)

Tests if your client accepts tokens where RS256 was changed to HS256 and signed with the public key.

```typescript
it("should reject key confusion attack", async () => {
  const session = loki.createSession({
    name: "key-confusion-test",
    mode: "explicit",
    mischief: ["key-confusion"],
  });

  const token = await getMaliciousToken(session.id);

  // Verify attack was applied
  const [header] = token.split(".");
  const decoded = JSON.parse(atob(header));
  expect(decoded.alg).toBe("HS256"); // Changed from RS256

  // YOUR TEST: Verify your client rejects it
  await expect(yourClient.validateToken(token)).rejects.toThrow();
});
```

**What this tests:**
- RFC 7515 Section 4.1.1 compliance
- CWE-327: Algorithm confusion vulnerability

### 3. Temporal Attacks

Tests if your client properly validates token timestamps.

```typescript
it("should reject expired tokens", async () => {
  const session = loki.createSession({
    name: "expired-token-test",
    mode: "explicit",
    mischief: ["temporal-tampering"],
  });

  const token = await getMaliciousToken(session.id);

  // Token will have exp in the past
  const [, payload] = token.split(".");
  const claims = JSON.parse(atob(payload));
  expect(claims.exp).toBeLessThan(Math.floor(Date.now() / 1000));

  // YOUR TEST: Verify your client rejects it
  await expect(yourClient.validateToken(token)).rejects.toThrow(/expired/i);
});
```

**What this tests:**
- RFC 7519 Section 4.1.4 (exp claim)
- OIDC Core 1.0 Section 3.1.3.7 (ID Token validation)

### 4. Latency Testing

Tests if your client handles slow IdP responses properly.

```typescript
it("should timeout on slow responses", async () => {
  const session = loki.createSession({
    name: "latency-test",
    mode: "explicit",
    mischief: ["latency-injection"],
  });

  // Configure your client with a short timeout
  const clientWithTimeout = createClient({ timeout: 1000 });

  // Loki will delay the response
  await expect(
    clientWithTimeout.getToken(session.id)
  ).rejects.toThrow(/timeout/i);
});
```

## Session Modes

### Explicit Mode

You control exactly which attacks are active.

```typescript
const session = loki.createSession({
  mode: "explicit",
  mischief: ["alg-none", "temporal-tampering"], // Both active
});
```

### Random Mode

Randomly applies attacks based on probability.

```typescript
const session = loki.createSession({
  mode: "random",
  mischief: ["alg-none", "key-confusion", "temporal-tampering"],
  probability: 0.5, // 50% chance of mischief on each request
});

// Good for fuzz testing - run many requests
for (let i = 0; i < 100; i++) {
  const token = await getMaliciousToken(session.id);
  // Some will be malicious, some won't
}
```

### Shuffled Mode

Cycles through attacks in random order, one per request.

```typescript
const session = loki.createSession({
  mode: "shuffled",
  mischief: ["alg-none", "key-confusion", "temporal-tampering"],
});

// First request: one random attack
// Second request: different attack
// Third request: last remaining attack
// Fourth request onwards: no more attacks (queue exhausted)
```

## Reading the Ledger

After running tests, inspect what happened:

```typescript
it("should track all mischief in ledger", async () => {
  const session = loki.createSession({
    mode: "explicit",
    mischief: ["alg-none"],
  });

  await getMaliciousToken(session.id);
  await getMaliciousToken(session.id);

  const ledger = session.getLedger();

  // Summary statistics
  expect(ledger.summary.totalRequests).toBe(2);
  expect(ledger.summary.requestsWithMischief).toBe(2);
  expect(ledger.summary.mischiefByPlugin["alg-none"]).toBe(2);

  // Detailed entries
  for (const entry of ledger.entries) {
    console.log(`
      Request: ${entry.requestId}
      Plugin: ${entry.plugin.name}
      Mutation: ${entry.evidence.mutation}
      RFC: ${entry.spec.rfc}
    `);
  }
});
```

## Best Practices

### 1. Isolate Tests

Each test should create its own session:

```typescript
it("test 1", async () => {
  const session = loki.createSession({ ... });
  // Use session.id
});

it("test 2", async () => {
  const session = loki.createSession({ ... }); // Fresh session
  // Use session.id
});
```

### 2. Clean Up Between Test Runs

```typescript
afterEach(() => {
  loki.purgeSessions();
});
```

### 3. Test Both Positive and Negative

```typescript
it("should accept valid tokens", async () => {
  // No session header = no mischief
  const response = await fetch(`${ISSUER}/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${btoa("test-app:test-secret")}`,
      // No X-Loki-Session header
    },
    body: "grant_type=client_credentials",
  });

  const { access_token } = await response.json();

  // This token is valid - your client should accept it
  await expect(yourClient.validateToken(access_token)).resolves.toBeDefined();
});
```

### 4. Name Your Sessions

Names make debugging easier:

```typescript
const session = loki.createSession({
  name: "regression-test-#1234-alg-none",
  mode: "explicit",
  mischief: ["alg-none"],
});
```

## Integration with CI/CD

### Vitest Configuration

```typescript
// vitest.config.ts
export default {
  test: {
    testTimeout: 30000, // Loki needs time to start
    hookTimeout: 30000,
  },
};
```

### Parallel Test Execution

Use different ports for parallel test files:

```typescript
// test-file-1.test.ts
const PORT = 9001;

// test-file-2.test.ts
const PORT = 9002;
```

Or use dynamic port allocation:

```typescript
import { createServer } from "net";

async function getAvailablePort(): Promise<number> {
  return new Promise((resolve) => {
    const server = createServer();
    server.listen(0, () => {
      const port = (server.address() as any).port;
      server.close(() => resolve(port));
    });
  });
}

beforeAll(async () => {
  const port = await getAvailablePort();
  loki = new Loki({
    server: { port, host: "localhost" },
    provider: { issuer: `http://localhost:${port}`, ... },
  });
});
```

## Common Issues

### Token Not Modified

If your token isn't being modified:

1. Verify the session ID is correct in `X-Loki-Session` header
2. Check the session has mischief plugins enabled
3. Ensure you're hitting the `/token` endpoint

### Tests Interfering

If tests affect each other:

1. Use `persistence: { enabled: false }` in tests
2. Call `loki.purgeSessions()` in `beforeEach` or `afterEach`
3. Use unique session names

### Port Already in Use

Use unique ports per test file or dynamic port allocation (see above).
