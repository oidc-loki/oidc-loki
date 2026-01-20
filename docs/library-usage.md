# Library Usage Guide

This guide covers the programmatic API for using OIDC-Loki as a library in your test suites.

## Installation

```bash
npm install oidc-loki
```

## Core Concepts

### The Loki Class

The main entry point for all operations:

```typescript
import { Loki } from "oidc-loki";

const loki = new Loki(config);
await loki.start();
// ... use loki
await loki.stop();
```

### Sessions

Sessions isolate test scenarios and track which mischief was applied:

```typescript
const session = loki.createSession({
  name: "my-test",
  mode: "explicit",
  mischief: ["alg-none"],
});

// Use session.id in X-Loki-Session header
```

### Ledger

The ledger records every mischief application for auditing:

```typescript
const ledger = session.getLedger();
console.log(ledger.entries); // What happened
console.log(ledger.summary); // Aggregated stats
```

## Configuration Reference

### LokiConfig

```typescript
interface LokiConfig {
  server?: ServerConfig;
  provider: ProviderConfig;
  mischief?: MischiefConfig;
  plugins?: PluginsConfig;
  ledger?: LedgerConfig;
  persistence?: PersistenceConfig;
}
```

### ServerConfig

```typescript
interface ServerConfig {
  port: number;   // Default: 3000
  host: string;   // Default: "localhost"
}
```

### ProviderConfig

```typescript
interface ProviderConfig {
  issuer: string;           // OIDC issuer URL (must match server URL)
  clients: ClientConfig[];  // Registered clients
}

interface ClientConfig {
  client_id: string;
  client_secret?: string;
  redirect_uris?: string[];
  grant_types?: string[];   // Default: ["authorization_code"]
}
```

### PluginsConfig

```typescript
interface PluginsConfig {
  customDir?: string;   // Default: "./plugins"
  disabled?: string[];  // Plugin IDs to disable
}
```

### PersistenceConfig

```typescript
interface PersistenceConfig {
  enabled: boolean;  // Default: true
  path: string;      // Default: "./data/loki.db"
}
```

## API Reference

### Loki Class

#### Constructor

```typescript
const loki = new Loki(config: LokiConfig);
```

#### Lifecycle Methods

```typescript
// Start the server
await loki.start(): Promise<void>;

// Stop the server
await loki.stop(): Promise<void>;

// Check if running
loki.isRunning: boolean;

// Get server address
loki.address: string;  // e.g., "http://localhost:3000"

// Get issuer URL
loki.issuer: string;
```

#### Session Management

```typescript
// Create a new session
const session = loki.createSession(config?: Partial<SessionConfig>): SessionHandle;

// Get existing session
const session = loki.getSession(id: string): SessionHandle | undefined;

// List all sessions
const sessions = loki.listSessions(): Session[];

// Delete a session
loki.deleteSession(id: string): boolean;

// Purge all sessions
loki.purgeSessions(): void;
```

#### Plugin Management

```typescript
// Access plugin registry
loki.plugins: PluginRegistry;

// Check plugin count
loki.plugins.count: number;

// Check if plugin exists
loki.plugins.has("alg-none"): boolean;

// Get all plugins
loki.plugins.getAll(): MischiefPlugin[];

// Get plugins by phase
loki.plugins.getByPhase("token-signing"): MischiefPlugin[];

// Get plugins by severity
loki.plugins.getBySeverity("critical"): MischiefPlugin[];

// Register custom plugin programmatically
loki.register(plugin: MischiefPlugin): void;
```

### SessionHandle Class

```typescript
// Session ID (use in X-Loki-Session header)
session.id: string;

// Session mode
session.mode: "explicit" | "random" | "shuffled";

// Check if ended
session.isEnded: boolean;

// Enable a plugin (explicit mode only)
session.enable(pluginId: string, config?: object): void;

// Disable a plugin
session.disable(pluginId: string): void;

// Get the mischief ledger
session.getLedger(): MischiefLedger;

// End the session
session.end(): void;
```

### SessionConfig

```typescript
interface SessionConfig {
  name?: string;                                    // Human-readable name
  mode: "explicit" | "random" | "shuffled";         // Default: "explicit"
  mischief: string[];                               // Plugin IDs to enable
  probability?: number;                             // For random mode (0-1)
}
```

### MischiefLedger

```typescript
interface MischiefLedger {
  meta: {
    version: string;
    sessionId: string;
    sessionName?: string;
    mode: SessionMode;
    startedAt: string;
    endedAt?: string;
    lokiVersion: string;
  };
  summary: {
    totalRequests: number;
    requestsWithMischief: number;
    mischiefByPlugin: Record<string, number>;
    mischiefBySeverity: Record<Severity, number>;
  };
  entries: LedgerEntry[];
}
```

### LedgerEntry

```typescript
interface LedgerEntry {
  id: string;
  requestId: string;
  timestamp: string;
  plugin: {
    id: string;
    name: string;
    severity: Severity;
  };
  spec: {
    requirement: string;
    violation: string;
    rfc?: string;
    oidc?: string;
    cwe?: string;
  };
  evidence: Record<string, unknown>;
}
```

## Usage Examples

### Basic Test Setup

```typescript
import { Loki } from "oidc-loki";
import { beforeAll, afterAll, describe, it, expect } from "vitest";

describe("Security Tests", () => {
  let loki: Loki;

  beforeAll(async () => {
    loki = new Loki({
      server: { port: 9000, host: "localhost" },
      provider: {
        issuer: "http://localhost:9000",
        clients: [
          {
            client_id: "test",
            client_secret: "secret",
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

  it("tests something", async () => {
    const session = loki.createSession({
      mode: "explicit",
      mischief: ["alg-none"],
    });
    // ... test code
  });
});
```

### Multiple Clients

```typescript
const loki = new Loki({
  server: { port: 9000, host: "localhost" },
  provider: {
    issuer: "http://localhost:9000",
    clients: [
      {
        client_id: "web-app",
        client_secret: "web-secret",
        redirect_uris: ["http://localhost:8080/callback"],
        grant_types: ["authorization_code"],
      },
      {
        client_id: "api-service",
        client_secret: "api-secret",
        grant_types: ["client_credentials"],
      },
    ],
  },
});
```

### Disabling Built-in Plugins

```typescript
const loki = new Loki({
  // ...
  plugins: {
    disabled: ["latency-injection"], // Don't load this plugin
  },
});
```

### Custom Plugin Directory

```typescript
const loki = new Loki({
  // ...
  plugins: {
    customDir: "./my-plugins", // Load plugins from here
  },
});
```

### Programmatic Plugin Registration

```typescript
const loki = new Loki(config);
await loki.start();

// Register a custom plugin at runtime
loki.register({
  id: "my-custom-attack",
  name: "My Custom Attack",
  severity: "high",
  phase: "token-claims",
  spec: {
    description: "Custom attack for specific scenario",
  },
  description: "Does something custom",
  async apply(ctx) {
    if (!ctx.token) {
      return { applied: false, mutation: "No token", evidence: {} };
    }

    // Modify the token
    ctx.token.claims.custom = "malicious";

    return {
      applied: true,
      mutation: "Added malicious claim",
      evidence: { addedClaim: "custom" },
    };
  },
});
```

### Session with Random Mode

```typescript
const session = loki.createSession({
  name: "fuzz-test",
  mode: "random",
  mischief: ["alg-none", "key-confusion", "temporal-tampering"],
  probability: 0.3, // 30% chance of mischief
});

// Run many requests - some will have mischief
for (let i = 0; i < 100; i++) {
  const token = await getToken(session.id);
  // Test your client's handling
}

// Check what happened
const ledger = session.getLedger();
console.log(`Applied mischief to ${ledger.summary.requestsWithMischief} of 100 requests`);
```

### Inspecting the Ledger

```typescript
const session = loki.createSession({
  name: "detailed-test",
  mode: "explicit",
  mischief: ["alg-none", "temporal-tampering"],
});

// Make some requests
await getToken(session.id);
await getToken(session.id);

// Get the ledger
const ledger = session.getLedger();

// Summary
console.log("Total requests:", ledger.summary.totalRequests);
console.log("Mischief count:", ledger.summary.requestsWithMischief);
console.log("By plugin:", ledger.summary.mischiefByPlugin);
console.log("By severity:", ledger.summary.mischiefBySeverity);

// Detailed entries
for (const entry of ledger.entries) {
  console.log(`
    Time: ${entry.timestamp}
    Plugin: ${entry.plugin.name} (${entry.plugin.severity})
    Mutation: ${entry.evidence.mutation}
    RFC: ${entry.spec.rfc || "N/A"}
    CWE: ${entry.spec.cwe || "N/A"}
  `);
}
```

### Using Persistence

```typescript
// First run - create sessions
const loki1 = new Loki({
  // ...
  persistence: {
    enabled: true,
    path: "./test-data/loki.db",
  },
});
await loki1.start();

const session = loki1.createSession({ name: "persistent-test" });
console.log("Session ID:", session.id);

await loki1.stop();

// Second run - sessions are restored
const loki2 = new Loki({
  // ...
  persistence: {
    enabled: true,
    path: "./test-data/loki.db",
  },
});
await loki2.start();

// Session still exists!
const restored = loki2.getSession(session.id);
console.log("Restored session:", restored?.id);
```

## TypeScript Support

OIDC-Loki is written in TypeScript and exports all types:

```typescript
import {
  // Core
  Loki,
  SessionHandle,

  // Types
  type LokiConfig,
  type SessionConfig,
  type Session,
  type SessionMode,

  // Plugin types
  type MischiefPlugin,
  type MischiefContext,
  type MischiefResult,
  type TokenContext,
  type JWTHeader,
  type JWTClaims,

  // Ledger types
  type MischiefLedger,
  type LedgerEntry,

  // Utilities
  PluginRegistry,
} from "oidc-loki";
```

## Error Handling

```typescript
try {
  await loki.start();
} catch (err) {
  if (err.code === "EADDRINUSE") {
    console.error("Port already in use");
  }
  throw err;
}
```

Session errors:

```typescript
const session = loki.createSession({ mode: "explicit" });

try {
  // This throws in non-explicit modes
  session.enable("alg-none");
} catch (err) {
  console.error(err.message); // "Cannot enable plugins in random mode"
}
```
