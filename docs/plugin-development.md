# Plugin Development Guide

This guide explains how to create custom mischief plugins for OIDC-Loki.

## Plugin Architecture

Plugins are the core extension mechanism in OIDC-Loki. Each plugin:

1. Targets a specific **phase** of the OIDC flow
2. Applies a specific **mutation** to tokens or responses
3. Records **evidence** for the audit ledger
4. References relevant **specifications** (RFCs, CWEs)

## Plugin Interface

```typescript
interface MischiefPlugin {
  id: string;                              // Unique identifier
  name: string;                            // Human-readable name
  severity: "critical" | "high" | "medium" | "low";
  phase: "token-signing" | "token-claims" | "response" | "discovery";
  spec: SpecReference;                     // RFC/CWE references
  description: string;                     // What this plugin does
  apply(context: MischiefContext): Promise<MischiefResult>;
}

interface SpecReference {
  rfc?: string;          // e.g., "RFC 8725 Section 3.1"
  oidc?: string;         // e.g., "OIDC Core 1.0 Section 3.1.3.7"
  cwe?: string;          // e.g., "CWE-347"
  description: string;   // What the spec requires
}
```

## Plugin Phases

### token-signing

Intercepts JWT signing. Has access to header, claims, and signing functions.

```typescript
const signingPlugin: MischiefPlugin = {
  id: "my-signing-plugin",
  phase: "token-signing",
  // ...
  async apply(ctx) {
    if (!ctx.token) {
      return { applied: false, mutation: "No token", evidence: {} };
    }

    // Modify header
    ctx.token.header.alg = "none";

    // Modify signature
    ctx.token.signature = "";

    // Or re-sign with different key
    await ctx.token.sign("HS256", "secret-key");

    return {
      applied: true,
      mutation: "Changed signing algorithm",
      evidence: { newAlg: "none" },
    };
  },
};
```

### token-claims

Modifies JWT payload/claims.

```typescript
const claimsPlugin: MischiefPlugin = {
  id: "my-claims-plugin",
  phase: "token-claims",
  // ...
  async apply(ctx) {
    if (!ctx.token) {
      return { applied: false, mutation: "No token", evidence: {} };
    }

    // Modify claims
    const originalExp = ctx.token.claims.exp;
    ctx.token.claims.exp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago

    return {
      applied: true,
      mutation: "Set token as expired",
      evidence: { originalExp, newExp: ctx.token.claims.exp },
    };
  },
};
```

### response

Affects HTTP response behavior.

```typescript
const responsePlugin: MischiefPlugin = {
  id: "my-response-plugin",
  phase: "response",
  // ...
  async apply(ctx) {
    if (!ctx.response) {
      return { applied: false, mutation: "No response context", evidence: {} };
    }

    // Add delay
    await ctx.response.delay(5000); // 5 second delay

    return {
      applied: true,
      mutation: "Added 5s delay",
      evidence: { delayMs: 5000 },
    };
  },
};
```

### discovery

Modifies OIDC discovery document (`.well-known/openid-configuration`).

```typescript
const discoveryPlugin: MischiefPlugin = {
  id: "my-discovery-plugin",
  phase: "discovery",
  // ...
  async apply(ctx) {
    // Coming soon - discovery interception
    return { applied: false, mutation: "Not implemented", evidence: {} };
  },
};
```

## Context Objects

### TokenContext

Available in `token-signing` and `token-claims` phases:

```typescript
interface TokenContext {
  header: JWTHeader;     // Mutable JWT header
  claims: JWTClaims;     // Mutable JWT claims
  signature: string;     // Get/set signature directly
  getPublicKey(): Promise<string>;  // Get IdP's public key (PEM)
  sign(alg: string, key: string | Buffer): void;  // Re-sign token
}

interface JWTHeader {
  alg: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

interface JWTClaims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: unknown;
}
```

### ResponseContext

Available in `response` phase:

```typescript
interface ResponseContext {
  status: number;
  headers: Record<string, string>;
  body: unknown;
  delay(ms: number): Promise<void>;
}
```

### MischiefContext

Full context passed to `apply()`:

```typescript
interface MischiefContext {
  token?: TokenContext;       // For token phases
  response?: ResponseContext; // For response phase
  config: PluginConfig;       // Plugin-specific config
  session: SessionInfo;       // Current session info
}

interface SessionInfo {
  id: string;
  name?: string;
  mode: "explicit" | "random" | "shuffled";
}
```

## Creating a Custom Plugin

### Step 1: Create the Plugin File

Create a file in your plugins directory (default: `./plugins`):

```typescript
// plugins/audience-injection.js

export const audienceInjectionPlugin = {
  id: "audience-injection",
  name: "Audience Injection",
  severity: "high",
  phase: "token-claims",

  spec: {
    rfc: "RFC 7519 Section 4.1.3",
    oidc: "OIDC Core 1.0 Section 2",
    cwe: "CWE-284",
    description: "JWT 'aud' claim must match the intended recipient",
  },

  description: "Injects additional audiences into the token to test aud validation",

  async apply(ctx) {
    if (!ctx.token) {
      return { applied: false, mutation: "No token context", evidence: {} };
    }

    const originalAud = ctx.token.claims.aud;

    // Inject additional audience
    if (Array.isArray(ctx.token.claims.aud)) {
      ctx.token.claims.aud.push("https://attacker.com");
    } else if (ctx.token.claims.aud) {
      ctx.token.claims.aud = [ctx.token.claims.aud, "https://attacker.com"];
    } else {
      ctx.token.claims.aud = "https://attacker.com";
    }

    return {
      applied: true,
      mutation: "Injected malicious audience",
      evidence: {
        originalAud,
        newAud: ctx.token.claims.aud,
        injected: "https://attacker.com",
      },
    };
  },
};
```

### Step 2: Configure Plugin Discovery

```typescript
const loki = new Loki({
  // ...
  plugins: {
    customDir: "./plugins", // Path to your plugins
  },
});
```

### Step 3: Use the Plugin

```typescript
const session = loki.createSession({
  mode: "explicit",
  mischief: ["audience-injection"], // Your plugin ID
});
```

## Multiple Plugins Per File

You can export multiple plugins from one file:

```typescript
// plugins/timing-attacks.js

export const expiredToken = {
  id: "expired-token",
  name: "Expired Token",
  severity: "high",
  phase: "token-claims",
  spec: { description: "Token exp claim validation" },
  description: "Sets exp to past time",
  async apply(ctx) {
    if (!ctx.token) return { applied: false, mutation: "No token", evidence: {} };
    ctx.token.claims.exp = Math.floor(Date.now() / 1000) - 3600;
    return { applied: true, mutation: "Token expired", evidence: {} };
  },
};

export const futureToken = {
  id: "future-token",
  name: "Future Token",
  severity: "medium",
  phase: "token-claims",
  spec: { description: "Token nbf claim validation" },
  description: "Sets nbf to future time",
  async apply(ctx) {
    if (!ctx.token) return { applied: false, mutation: "No token", evidence: {} };
    ctx.token.claims.nbf = Math.floor(Date.now() / 1000) + 3600;
    return { applied: true, mutation: "Token not yet valid", evidence: {} };
  },
};
```

## Default Export

You can also use default export:

```typescript
// plugins/single-plugin.js

export default {
  id: "single-plugin",
  name: "Single Plugin",
  // ...
};
```

## Plugin Registration at Runtime

Instead of file-based discovery, register plugins programmatically:

```typescript
const loki = new Loki(config);
await loki.start();

loki.register({
  id: "runtime-plugin",
  name: "Runtime Plugin",
  severity: "low",
  phase: "response",
  spec: { description: "Test plugin" },
  description: "Added at runtime",
  async apply(ctx) {
    return { applied: true, mutation: "Runtime mischief", evidence: {} };
  },
});
```

## Best Practices

### 1. Always Check Context

```typescript
async apply(ctx) {
  if (!ctx.token) {
    return { applied: false, mutation: "No token context", evidence: {} };
  }
  // ... rest of logic
}
```

### 2. Preserve Original Values in Evidence

```typescript
async apply(ctx) {
  const originalAlg = ctx.token.header.alg;
  ctx.token.header.alg = "none";

  return {
    applied: true,
    mutation: `Changed alg from ${originalAlg} to none`,
    evidence: {
      originalAlg,
      newAlg: "none",
    },
  };
}
```

### 3. Reference Specifications

```typescript
spec: {
  rfc: "RFC 8725 Section 3.1",  // JWT Best Practices
  cwe: "CWE-327",               // Broken Crypto
  description: "JWTs MUST validate the algorithm header",
},
```

### 4. Use Appropriate Severity

- **critical**: Complete authentication bypass, signature bypass
- **high**: Token expiration bypass, audience bypass
- **medium**: Information disclosure, timing issues
- **low**: Minor protocol deviations

### 5. Make Mutations Idempotent

Plugins may be called multiple times per request (if multiple plugins enabled):

```typescript
async apply(ctx) {
  // Check if already modified
  if (ctx.token.header.alg === "none") {
    return { applied: false, mutation: "Already modified", evidence: {} };
  }

  ctx.token.header.alg = "none";
  // ...
}
```

## Example: Complete Plugin

```typescript
// plugins/issuer-spoofing.js

import { MischiefPlugin } from "oidc-loki";

export const issuerSpoofingPlugin: MischiefPlugin = {
  id: "issuer-spoofing",
  name: "Issuer Spoofing",
  severity: "critical",
  phase: "token-claims",

  spec: {
    rfc: "RFC 7519 Section 4.1.1",
    oidc: "OIDC Core 1.0 Section 3.1.3.7",
    cwe: "CWE-290",
    description: "The 'iss' claim MUST match the expected issuer",
  },

  description: "Changes the issuer claim to test iss validation",

  async apply(ctx) {
    if (!ctx.token) {
      return {
        applied: false,
        mutation: "No token context available",
        evidence: {},
      };
    }

    const originalIss = ctx.token.claims.iss;
    const spoofedIss = "https://evil-issuer.attacker.com";

    ctx.token.claims.iss = spoofedIss;

    return {
      applied: true,
      mutation: `Spoofed issuer from '${originalIss}' to '${spoofedIss}'`,
      evidence: {
        originalIssuer: originalIss,
        spoofedIssuer: spoofedIss,
        attackType: "issuer-spoofing",
      },
    };
  },
};
```

## Testing Your Plugin

```typescript
import { Loki } from "oidc-loki";
import { describe, it, expect, beforeAll, afterAll } from "vitest";

describe("Issuer Spoofing Plugin", () => {
  let loki: Loki;

  beforeAll(async () => {
    loki = new Loki({
      server: { port: 9999, host: "localhost" },
      provider: {
        issuer: "http://localhost:9999",
        clients: [{ client_id: "test", client_secret: "secret", grant_types: ["client_credentials"] }],
      },
      plugins: { customDir: "./plugins" },
      persistence: { enabled: false, path: "" },
    });
    await loki.start();
  });

  afterAll(async () => {
    await loki.stop();
  });

  it("should spoof the issuer", async () => {
    const session = loki.createSession({
      mode: "explicit",
      mischief: ["issuer-spoofing"],
    });

    const response = await fetch("http://localhost:9999/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${btoa("test:secret")}`,
        "X-Loki-Session": session.id,
      },
      body: "grant_type=client_credentials",
    });

    const { access_token } = await response.json();
    const [, payload] = access_token.split(".");
    const claims = JSON.parse(atob(payload));

    expect(claims.iss).toBe("https://evil-issuer.attacker.com");

    // Check ledger
    const ledger = session.getLedger();
    expect(ledger.entries[0].plugin.id).toBe("issuer-spoofing");
    expect(ledger.entries[0].evidence.spoofedIssuer).toBe("https://evil-issuer.attacker.com");
  });
});
```
