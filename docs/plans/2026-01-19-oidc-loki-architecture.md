# OIDC-Loki: System Architecture Document

> **Version:** 1.0.0
> **Date:** 2026-01-19
> **Status:** Approved

---

## Executive Summary

OIDC-Loki is a **Security Chaos Engineering** tool for OIDC/OAuth2. It functions as a "Bad Identity Provider" that can be programmatically configured to violate OIDC and OAuth2 specifications, enabling teams to test whether their client applications properly reject malformed tokens, handle edge cases, and fail safely when an IdP misbehaves.

This is the identity equivalent of Netflix's Chaos Monkey—deliberately injecting failures to build confidence in system resilience.

---

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Deployment Model | Library + Standalone | Max flexibility: embed in test suites or run as persistent service |
| Mischief Triggering | Layered (Server → Profile → Header) | Supports both "set and forget" campaigns and precise test assertions |
| Mischief Composability | Composable with Attribution | Real attacks chain vectors; reports attribute failures to specific plugins |
| Blind Test Modes | Random + Shuffled | Random chaos (probabilistic) and shuffled playlist (deterministic coverage, random order) |
| Reporting Model | Mischief Ledger | Loki logs what it did; client asserts on its own behavior. Optional outcome callback for aggregation. |
| Persistence | SQLite with Purge | Sessions persist across restarts; purge endpoints for cleanup |
| Plugin Loading | Built-in + File Discovery + Programmatic | Core attacks included, extensible via filesystem or code registration |

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                           OIDC-Loki                                  │
├──────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌────────────────────────┐   │
│  │   Hono API  │───▶│   Mischief  │───▶│   node-oidc-provider   │   │
│  │  (Control)  │    │   Engine    │    │       (Core IdP)       │   │
│  └─────────────┘    └─────────────┘    └────────────────────────┘   │
│         │                 │                       │                 │
│         ▼                 ▼                       ▼                 │
│  ┌─────────────┐    ┌─────────────┐    ┌────────────────────────┐   │
│  │   Session   │    │   Plugin    │    │     Token Forge        │   │
│  │   Manager   │    │   Registry  │    │   (JWT Manipulation)   │   │
│  └─────────────┘    └─────────────┘    └────────────────────────┘   │
│         │                                         │                 │
│         ▼                                         ▼                 │
│  ┌────────────────────────────────────────────────┘                 │
│  │              Mischief Ledger                                     │
│  │         (JSON / JUnit XML Export)                                │
│  └──────────────────────────────────────────────────────────────────│
│                               │                                     │
│                               ▼                                     │
│  ┌──────────────────────────────────────────────────────────────────│
│  │              SQLite Persistence                                  │
│  │         (Sessions, Ledger Entries)                               │
│  └──────────────────────────────────────────────────────────────────│
└──────────────────────────────────────────────────────────────────────┘
```

### Core Components

| Component | Responsibility |
|-----------|----------------|
| **Hono API** | Control plane for admin operations (sessions, config, reports) |
| **Mischief Engine** | Intercepts IdP operations, applies active plugins in sequence |
| **node-oidc-provider** | Legitimate OIDC implementation that Loki deliberately corrupts |
| **Plugin Registry** | Manages built-in, discovered, and programmatically registered plugins |
| **Token Forge** | Low-level JWT manipulation (headers, claims, signatures) |
| **Session Manager** | Groups requests into test sessions, tracks mischief applied |
| **Mischief Ledger** | Records what mischief was applied; exports logs for client-side analysis |
| **Persistence Layer** | SQLite storage for sessions and ledger entries |

---

## Directory Structure

```
oidc-loki/
├── src/
│   ├── index.ts                 # Library entry point (programmatic API)
│   ├── server.ts                # Standalone server entry point
│   │
│   ├── core/
│   │   ├── loki.ts              # Main Loki class (library mode)
│   │   ├── mischief-engine.ts   # Intercepts & applies mischief
│   │   ├── token-forge.ts       # JWT manipulation primitives
│   │   └── provider-adapter.ts  # Wraps node-oidc-provider
│   │
│   ├── plugins/
│   │   ├── registry.ts          # Plugin discovery & registration
│   │   ├── types.ts             # MischiefPlugin interface
│   │   ├── built-in/
│   │   │   ├── index.ts         # Exports all built-in plugins
│   │   │   ├── alg-none.ts
│   │   │   ├── key-confusion.ts
│   │   │   ├── latency-injection.ts
│   │   │   └── temporal-tampering.ts
│   │   └── custom/              # Bundled custom plugins (file discovery)
│   │       └── .gitkeep
│   │
│   ├── api/
│   │   ├── routes.ts            # Hono route definitions
│   │   ├── admin.ts             # /admin/* endpoints
│   │   └── middleware.ts        # Session tracking, header parsing
│   │
│   ├── sessions/
│   │   ├── manager.ts           # Session lifecycle
│   │   ├── modes.ts             # explicit | random | shuffled
│   │   └── store.ts             # SQLite-backed session store
│   │
│   ├── persistence/
│   │   ├── database.ts          # SQLite connection & migrations
│   │   └── schema.ts            # Table definitions
│   │
│   └── ledger/
│       ├── writer.ts            # Records mischief events
│       ├── formats/
│       │   ├── json.ts          # Mischief Ledger (JSON)
│       │   └── junit.ts         # JUnit XML for CI
│       └── types.ts             # Ledger schema types
│
├── plugins/                     # External plugin directory (user drops here)
│   └── .gitkeep
│
├── docs/
│   └── plans/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│
├── package.json
├── tsconfig.json
├── biome.json
└── README.md
```

---

## Plugin Architecture

### MischiefPlugin Interface

```typescript
interface MischiefPlugin {
  /** Unique identifier, e.g., "alg-none" */
  id: string;

  /** Human-readable name */
  name: string;

  /** RFC/spec reference for the violation */
  spec: SpecReference;

  /** Severity: how bad is it if a client accepts this? */
  severity: 'critical' | 'high' | 'medium' | 'low';

  /** What this plugin does (for reports) */
  description: string;

  /** Which phase of the OIDC flow this intercepts */
  phase: 'token-signing' | 'token-claims' | 'response' | 'discovery';

  /** The actual mischief logic */
  apply(context: MischiefContext): Promise<MischiefResult>;
}

interface SpecReference {
  rfc?: string;          // e.g., "RFC 8725 Section 3.1"
  oidc?: string;         // e.g., "OIDC Core 1.0 Section 3.1.3.7"
  cwe?: string;          // e.g., "CWE-347"
  description: string;   // What the spec actually requires
}

interface MischiefContext {
  token?: TokenContext;       // JWT being forged
  response?: ResponseContext; // HTTP response being sent
  config: PluginConfig;       // Plugin-specific settings
  session: SessionInfo;       // Current test session
}

interface MischiefResult {
  applied: boolean;           // Did mischief actually occur?
  mutation: string;           // What changed (for attribution)
  evidence: Record<string, unknown>; // Proof for the report
}
```

### Plugin Discovery Order

1. **Built-in plugins** - Loaded from `src/plugins/built-in/`
2. **Bundled custom** - Discovered from `src/plugins/custom/`
3. **External plugins** - Discovered from `plugins/` (configurable)
4. **Programmatic** - Registered via `loki.register(plugin)`

Later registrations can override earlier ones by `id`.

---

## Built-in Plugins (Initial Mischief Backlog)

### alg-none (Critical)

| Field | Value |
|-------|-------|
| **ID** | `alg-none` |
| **Phase** | `token-signing` |
| **Spec** | RFC 8725 Section 3.1, CWE-327 |
| **Attack** | Sets JWT `alg` header to `"none"`, removes signature |
| **Pass Condition** | Client rejects unsigned token |

### key-confusion (Critical)

| Field | Value |
|-------|-------|
| **ID** | `key-confusion` |
| **Phase** | `token-signing` |
| **Spec** | RFC 7515 Section 4.1.1, CWE-347 |
| **Attack** | Changes RS256 to HS256, signs with RSA public key as HMAC secret |
| **Pass Condition** | Client rejects mismatched algorithm/key |

### latency-injection (Medium)

| Field | Value |
|-------|-------|
| **ID** | `latency-injection` |
| **Phase** | `response` |
| **Spec** | OIDC Core 1.0 Section 3.1.2.1 |
| **Attack** | Delays response by configurable duration (default 5s) |
| **Pass Condition** | Client times out gracefully, doesn't hang indefinitely |
| **Config** | `{ delayMs: number }` |

### temporal-tampering (High)

| Field | Value |
|-------|-------|
| **ID** | `temporal-tampering` |
| **Phase** | `token-claims` |
| **Spec** | RFC 7519 Section 4.1.4, CWE-613 |
| **Attack** | Sets `exp` to past, `nbf` to future, or `iat` to future |
| **Pass Condition** | Client rejects temporally invalid tokens |
| **Config** | `{ mode: 'expired' \| 'future' \| 'issued-future' }` |

---

## Session Modes

Sessions operate in one of three modes:

### Explicit Mode (Default)

Client controls exactly which mischief is applied per request via headers or API.

```typescript
{
  mode: "explicit",
  mischief: ["alg-none"]  // Only what's explicitly enabled
}
```

**Use case:** Unit tests, debugging specific vulnerabilities.

### Random Mode (Chaos Monkey)

Loki randomly selects from the enabled mischief pool for each request.

```typescript
{
  mode: "random",
  mischief: ["alg-none", "key-confusion", "temporal-tampering"],
  probability: 0.5  // 50% chance any request gets hit
}
```

**Behavior:**
- Each request: roll dice → if hit, pick random mischief from pool
- Multiple mischief can stack (composable)
- Client has no idea what's coming

**Use case:** Integration tests, "can this client survive a hostile IdP?"

### Shuffled Mode (Playlist)

Loki applies each enabled mischief exactly once, in random order.

```typescript
{
  mode: "shuffled",
  mischief: ["alg-none", "key-confusion", "temporal-tampering", "latency-injection"]
}
```

**Behavior:**
- Creates randomized queue: e.g., `[key-confusion, latency-injection, alg-none, temporal-tampering]`
- Each request pops next item from queue
- Guarantees full coverage, unpredictable order
- After queue exhausted: recycles (reshuffles) or stops (configurable)

**Use case:** E2E test suites, compliance testing, "test all attacks without client knowing order."

---

## Mischief Ledger Schema

The ledger records what Loki did - the client determines pass/fail via its own assertions.

```typescript
interface MischiefLedger {
  /** Ledger metadata */
  meta: {
    version: "1.0.0";
    sessionId: string;
    sessionName?: string;
    mode: "explicit" | "random" | "shuffled";
    startedAt: string;          // ISO 8601
    endedAt?: string;
    lokiVersion: string;
  };

  /** Summary stats */
  summary: {
    totalRequests: number;
    requestsWithMischief: number;
    mischiefByPlugin: Record<string, number>;  // { "alg-none": 5, "key-confusion": 3 }
    mischiefBySeverity: Record<string, number>; // { "critical": 8, "high": 2 }
  };

  /** Every mischief event */
  entries: LedgerEntry[];
}

interface LedgerEntry {
  id: string;                   // Unique entry ID
  requestId: string;            // Links to request
  timestamp: string;

  /** What mischief was applied */
  plugin: {
    id: string;
    name: string;
    severity: "critical" | "high" | "medium" | "low";
  };

  /** Spec violation reference */
  spec: {
    rfc?: string;
    oidc?: string;
    cwe?: string;
    requirement: string;        // What the spec says
    violation: string;          // What Loki did
  };

  /** Evidence of mutation */
  evidence: {
    mutation: string;           // Human-readable description
    original?: unknown;         // Before state
    mutated?: unknown;          // After state
  };

  /** Plugin config used */
  config?: Record<string, unknown>;
}

/** Optional: Client can POST outcomes back */
interface OutcomeReport {
  requestId: string;
  accepted: boolean;            // Did client accept the bad token?
  error?: string;               // Error message if client errored
  notes?: string;               // Additional context
}
```

### Key Difference from "Resilience Report"

- **No pass/fail/score** - Loki doesn't judge; it just records
- **Client owns assertions** - Test harness says "I should have rejected that"
- **Optional feedback loop** - `POST /admin/sessions/:id/outcomes` for clients that want aggregated dashboards

---

## Configuration Schema

```typescript
interface LokiConfig {
  /** Server settings (standalone mode only) */
  server?: {
    port: number;               // Default: 3000
    host: string;               // Default: "localhost"
  };

  /** Base OIDC provider settings */
  provider: {
    issuer: string;             // e.g., "http://localhost:3000"
    clients: ClientConfig[];    // Pre-registered test clients
  };

  /** Default mischief (server-level) */
  mischief: {
    enabled: string[];          // Plugin IDs active by default
    profiles: Record<string, string[]>;  // Named attack combinations
  };

  /** Plugin discovery */
  plugins: {
    customDir?: string;         // Default: "./plugins"
    disabled?: string[];        // Built-ins to disable
  };

  /** Ledger export */
  ledger: {
    autoExport?: boolean;       // Export on session end
    exportPath?: string;        // Default: "./ledger"
    formats: ("json" | "junit")[];
  };

  /** Persistence */
  persistence: {
    enabled: boolean;           // Default: true
    path: string;               // Default: "./data/loki.db"
  };
}

interface ClientConfig {
  client_id: string;
  client_secret?: string;
  redirect_uris?: string[];
  grant_types?: string[];
}
```

### Example Configuration

```json
{
  "server": {
    "port": 3000,
    "host": "localhost"
  },
  "provider": {
    "issuer": "http://localhost:3000",
    "clients": [
      {
        "client_id": "test-app",
        "client_secret": "test-secret",
        "redirect_uris": ["http://localhost:8080/callback"],
        "grant_types": ["authorization_code", "client_credentials"]
      }
    ]
  },
  "mischief": {
    "enabled": [],
    "profiles": {
      "chaos-level-1": ["temporal-tampering", "latency-injection"],
      "chaos-level-2": ["alg-none", "key-confusion"],
      "full-madness": ["alg-none", "key-confusion", "temporal-tampering", "latency-injection"]
    }
  },
  "plugins": {
    "customDir": "./plugins"
  },
  "ledger": {
    "autoExport": true,
    "exportPath": "./ledger",
    "formats": ["json", "junit"]
  },
  "persistence": {
    "enabled": true,
    "path": "./data/loki.db"
  }
}
```

---

## API Reference

### OIDC Standard Endpoints

Served by `node-oidc-provider`, intercepted by Mischief Engine:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/.well-known/openid-configuration` | Discovery document |
| GET | `/jwks` | JSON Web Key Set |
| POST | `/token` | Token endpoint |
| GET | `/authorize` | Authorization endpoint |
| POST | `/userinfo` | UserInfo endpoint |

### Loki Admin API

| Method | Endpoint | Description |
|--------|----------|-------------|
| **Sessions** |
| POST | `/admin/sessions` | Create session `{ name, mode, mischief, probability? }` |
| GET | `/admin/sessions` | List all sessions |
| GET | `/admin/sessions/:id` | Get session status |
| DELETE | `/admin/sessions/:id` | End session |
| POST | `/admin/sessions/:id/outcomes` | (Optional) Report client outcomes |
| **Mischief Config** |
| POST | `/admin/mischief` | Set server-level mischief |
| GET | `/admin/mischief` | Get current mischief config |
| POST | `/admin/mischief/profiles/:name` | Activate named profile |
| **Ledger & Reports** |
| GET | `/admin/ledger/:sessionId` | Get Mischief Ledger (JSON) |
| GET | `/admin/ledger/:sessionId/junit` | Get JUnit XML format |
| **Plugins** |
| GET | `/admin/plugins` | List available plugins |
| GET | `/admin/plugins/:id` | Get plugin details |
| **Persistence** |
| DELETE | `/admin/sessions` | Purge all sessions |
| POST | `/admin/reset` | Nuclear reset (wipe everything) |
| **Health** |
| GET | `/health` | Health check |

### Request Headers

| Header | Purpose | Example |
|--------|---------|---------|
| `X-Loki-Session` | Associate request with session | `X-Loki-Session: sess_abc123` |
| `X-Loki-Mischief` | Per-request mischief override | `X-Loki-Mischief: alg-none,latency-500` |
| `X-Loki-Profile` | Activate named profile | `X-Loki-Profile: chaos-level-1` |

### Header Priority (Layered Override)

```
Server Default → Profile Activation → Per-Request Header
```

Per-request headers have highest priority.

---

## Usage Examples

### Library Mode (Test Suite Integration)

```typescript
import { Loki } from "oidc-loki";

describe("OIDC Client Resilience", () => {
  let loki: Loki;

  beforeAll(async () => {
    loki = new Loki({
      provider: {
        issuer: "http://localhost:9999",
        clients: [{ client_id: "test", client_secret: "secret" }]
      }
    });
    await loki.start();
  });

  afterAll(() => loki.stop());

  // Explicit mode: precise control for unit tests
  it("rejects alg:none tokens", async () => {
    const session = loki.createSession({ mode: "explicit" });
    session.enable("alg-none");

    const result = await yourOidcClient.authenticate({
      issuer: loki.issuer,
      clientId: "test",
      clientSecret: "secret"
    });

    // Client should have rejected - YOU assert, not Loki
    expect(result.error).toBeDefined();
    expect(result.error).toMatch(/signature|algorithm/i);

    // Ledger confirms what Loki did
    const ledger = session.getLedger();
    expect(ledger.entries[0].plugin.id).toBe("alg-none");
  });

  // Shuffled mode: guaranteed coverage, random order
  it("survives all attacks (blind)", async () => {
    const session = loki.createSession({
      mode: "shuffled",
      mischief: ["alg-none", "key-confusion", "temporal-tampering"]
    });

    // Run 3 auth attempts - each gets a different attack
    for (let i = 0; i < 3; i++) {
      const result = await yourOidcClient.authenticate({
        issuer: loki.issuer,
        clientId: "test"
      });
      // Client should reject ALL of them
      expect(result.error).toBeDefined();
    }

    // Ledger shows all 3 attacks were applied
    const ledger = session.getLedger();
    const plugins = ledger.entries.map(e => e.plugin.id);
    expect(plugins).toContain("alg-none");
    expect(plugins).toContain("key-confusion");
    expect(plugins).toContain("temporal-tampering");
  });

  // Random mode: chaos monkey
  it("handles random chaos", async () => {
    const session = loki.createSession({
      mode: "random",
      mischief: ["alg-none", "key-confusion", "latency-injection"],
      probability: 0.8  // 80% of requests get hit
    });

    // Run many attempts
    for (let i = 0; i < 10; i++) {
      const result = await yourOidcClient.authenticate({
        issuer: loki.issuer,
        clientId: "test",
        timeout: 1000
      });
      // Some should fail, some might succeed (no mischief applied)
    }

    const ledger = session.getLedger();
    // Expect roughly 8 entries (80% of 10)
    expect(ledger.summary.requestsWithMischief).toBeGreaterThan(5);
  });
});
```

### Standalone Mode (CLI)

```bash
# Start Loki server
npx oidc-loki serve --config loki.config.json

# Create explicit session (precise control)
curl -X POST http://localhost:3000/admin/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "name": "unit-test-run",
    "mode": "explicit",
    "mischief": ["alg-none"]
  }'
# Returns: {"sessionId": "sess_abc123"}

# Create shuffled session (blind, full coverage)
curl -X POST http://localhost:3000/admin/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "name": "nightly-chaos-run",
    "mode": "shuffled",
    "mischief": ["alg-none", "key-confusion", "temporal-tampering", "latency-injection"]
  }'
# Returns: {"sessionId": "sess_def456"}

# Create random session (chaos monkey)
curl -X POST http://localhost:3000/admin/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "name": "chaos-monkey",
    "mode": "random",
    "mischief": ["alg-none", "key-confusion"],
    "probability": 0.5
  }'
# Returns: {"sessionId": "sess_ghi789"}

# Run your client's test suite against http://localhost:3000
# Include session header to associate requests
npm test -- --issuer=http://localhost:3000 --header="X-Loki-Session: sess_def456"

# Get the ledger
curl http://localhost:3000/admin/ledger/sess_def456 > ledger.json
curl http://localhost:3000/admin/ledger/sess_def456/junit > ledger.xml

# Cleanup
curl -X DELETE http://localhost:3000/admin/sessions/sess_def456  # Delete one
curl -X DELETE http://localhost:3000/admin/sessions              # Purge all
curl -X POST http://localhost:3000/admin/reset                   # Nuclear reset
```

---

## Compliance Mapping

All mischief plugins map to specific specification violations:

| Plugin | RFC 8725 | RFC 7519 | OIDC Core 1.0 | CWE |
|--------|----------|----------|---------------|-----|
| alg-none | Section 3.1 | - | - | CWE-327 |
| key-confusion | - | Section 4.1 | - | CWE-347 |
| temporal-tampering | - | Section 4.1.4 | - | CWE-613 |
| latency-injection | - | - | Section 3.1.2.1 | - |

---

## Technology Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| Runtime | Node.js 22+ | Latest LTS, native fetch, performance |
| HTTP Framework | Hono | Fast, lightweight, middleware-friendly |
| OIDC Engine | node-oidc-provider | Battle-tested, spec-compliant base |
| Linting | Biome | Fast, modern, all-in-one |
| Testing | Vitest | Fast, ESM-native, compatible API |
| TypeScript | 5.x | Strict mode, modern features |

---

## Implementation Phases

### Phase 1: Foundation (COMPLETE)
- [x] Project scaffolding (package.json, tsconfig, biome)
- [x] Core Loki class with start/stop lifecycle
- [ ] Basic node-oidc-provider integration
- [x] Plugin registry with built-in loading
- [x] Unit tests for core functionality

### Phase 2: Mischief Engine (COMPLETE)
- [x] Token Forge for JWT manipulation
- [x] Mischief Engine intercept pipeline
- [x] Implement: alg-none plugin (logic complete, wiring pending)
- [x] Implement: key-confusion plugin (logic complete, wiring pending)

### Phase 3: Session & Reporting
- [ ] Session Manager
- [ ] Request logging with mischief attribution
- [ ] JSON report generation
- [ ] JUnit XML export

### Phase 4: API & Standalone
- [ ] Hono admin API
- [ ] Header-based mischief override
- [ ] Profile system
- [ ] CLI entry point

### Phase 5: Remaining Plugins
- [ ] Implement: latency-injection
- [ ] Implement: temporal-tampering
- [ ] File-based plugin discovery

---

## Resolved Decisions

| Question | Resolution |
|----------|------------|
| **Client Feedback Loop** | Loki doesn't judge outcomes. Client owns assertions. Optional `POST /admin/sessions/:id/outcomes` for clients wanting aggregated dashboards. |
| **Persistence** | SQLite-backed with purge endpoints. `DELETE /admin/sessions` and `POST /admin/reset` for cleanup. |
| **Blind Testing** | Two modes: `random` (probabilistic chaos) and `shuffled` (deterministic coverage, random order). |

---

## Approval

- [x] Architecture approved for implementation
- [ ] Proceed with Phase 1

---

*Document generated by OIDC-Loki design session, 2026-01-19*
