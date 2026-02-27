# Plan 002: oidc-loki v0.2 -- Bidirectional Architecture (Phase C)

**Status:** Draft
**Priority:** P1
**Depends on:** Plan 001 (splice-check CLI proven out)
**Blocks:** None

---

## Goal

Evolve oidc-loki from a server-only tool (malicious IdP) into a bidirectional security testing platform: server-side plugins that attack RPs, and client-side plugins that attack ASes. Fold splice-check into oidc-loki as the first client-side plugin suite.

## Architecture

### Dual plugin model

Two distinct interfaces sharing a common base. Gemini and I both agree: don't stretch MischiefPlugin to cover client-side attacks. The operational flow is too different.

```typescript
// Shared base
interface LokiPlugin {
  id: string;
  name: string;
  description: string;
  spec: SpecReference;
  severity: Severity;
}

// Server-side: intercept and mutate outbound responses (existing)
interface MischiefPlugin extends LokiPlugin {
  direction: "server";
  phase: MischiefPhase;
  apply(ctx: MischiefContext): Promise<MischiefResult>;
}

// Client-side: craft and send inbound attack requests (new)
interface AttackPlugin extends LokiPlugin {
  direction: "client";
  setup(ctx: AttackContext): Promise<SetupResult>;
  attack(ctx: AttackContext, setup: SetupResult): Promise<AttackResponse>;
  verify(response: AttackResponse): TestVerdict;
}

// Union type for registry
type AnyPlugin = MischiefPlugin | AttackPlugin;
```

### Unified plugin registry

The existing `PluginRegistry` gains awareness of plugin direction:

```typescript
class PluginRegistry {
  // Existing methods still work
  getAll(): AnyPlugin[];
  getByPhase(phase: MischiefPhase): MischiefPlugin[];

  // New methods for client-side
  getServerPlugins(): MischiefPlugin[];
  getClientPlugins(): AttackPlugin[];
  getByDirection(dir: "server" | "client"): AnyPlugin[];
}
```

### Monorepo restructure

Move from flat `src/` to `packages/`:

```
oidc-loki/
├── packages/
│   ├── core/                    # Shared types, plugin interfaces, registry
│   │   ├── src/
│   │   │   ├── types.ts         # LokiPlugin, MischiefPlugin, AttackPlugin
│   │   │   ├── registry.ts      # Unified PluginRegistry
│   │   │   ├── config.ts        # ProviderConfig + TargetConfig
│   │   │   └── ledger.ts        # Unified ledger types
│   │   └── package.json
│   │
│   ├── server/                  # Malicious IdP (current src/)
│   │   ├── src/
│   │   │   ├── loki.ts
│   │   │   ├── server.ts
│   │   │   ├── mischief-engine.ts
│   │   │   └── plugins/         # 36 existing MischiefPlugins
│   │   └── package.json
│   │
│   ├── client/                  # Malicious client (from splice-check)
│   │   ├── src/
│   │   │   ├── runner.ts        # Test orchestrator
│   │   │   ├── oauth-client.ts  # HTTP client for token endpoints
│   │   │   └── plugins/         # AttackPlugins (splice-check tests + future)
│   │   └── package.json
│   │
│   └── cli/                     # Unified CLI
│       ├── src/
│       │   ├── index.ts         # Entry point
│       │   ├── server-cmd.ts    # oidc-loki server (existing behavior)
│       │   └── client-cmd.ts    # oidc-loki client splice-check
│       └── package.json
│
├── docker/                      # Docker Compose for test targets
│   ├── wso2/
│   └── keycloak/
│
├── pnpm-workspace.yaml
└── package.json
```

### Unified CLI

```
$ oidc-loki server                    # Start malicious IdP (existing behavior)
$ oidc-loki server --config loki.toml

$ oidc-loki client splice-check       # Run splice-check tests
$ oidc-loki client splice-check --config target.toml
$ oidc-loki client splice-check --format json

$ oidc-loki client [future-suite]     # Future client-side test suites
```

### Unified ledger

Both server and client results flow into the same ledger format:

```typescript
type LedgerEntry =
  | { type: "mischief"; pluginId: string; sessionId: string; result: MischiefResult; timestamp: string }
  | { type: "attack"; pluginId: string; target: string; verdict: TestVerdict; timestamp: string };
```

The ledger can export to JSON, JUnit XML (for CI), and markdown (for reports).

## Migration path from Phase B to Phase C

1. Extract shared types from `tools/splice-check/src/tests/types.ts` into `packages/core/`
2. Move `tools/splice-check/src/tests/*.ts` into `packages/client/src/plugins/`
3. Move `tools/splice-check/src/client.ts` into `packages/client/src/oauth-client.ts`
4. Move `tools/splice-check/src/runner.ts` into `packages/client/src/runner.ts`
5. Create `packages/cli/` with subcommands that delegate to server and client packages
6. Move existing `src/` into `packages/server/`
7. Update `package.json` bin entries: single `oidc-loki` binary with subcommands
8. Deprecate standalone `splice-check` binary (alias to `oidc-loki client splice-check`)

## Implementation steps

### Step 1: Define shared core
- [ ] Extract `LokiPlugin`, `MischiefPlugin`, `AttackPlugin` interfaces into `packages/core/`
- [ ] Extract `PluginRegistry` with direction-aware methods
- [ ] Define unified `LedgerEntry` type

### Step 2: Restructure server
- [ ] Move current `src/` to `packages/server/`
- [ ] Update imports to use `@oidc-loki/core`
- [ ] Verify all 36 existing plugins still work
- [ ] Run existing test suite

### Step 3: Port splice-check
- [ ] Move `tools/splice-check/` logic to `packages/client/`
- [ ] Update tests to implement `AttackPlugin` interface
- [ ] Verify all 9 tests still work against WSO2

### Step 4: Unified CLI
- [ ] Create `packages/cli/` with commander subcommands
- [ ] `server` subcommand delegates to `packages/server/`
- [ ] `client splice-check` subcommand delegates to `packages/client/`
- [ ] Single `oidc-loki` binary in package.json

### Step 5: Tooling
- [ ] Set up pnpm workspaces
- [ ] Configure TypeScript project references
- [ ] Ensure `npm run build` builds all packages
- [ ] Ensure `npm test` runs all test suites

## Risk

- Monorepo tooling adds complexity. Don't do this until Plan 001 is proven.
- Breaking changes to the library API (exported types move from `oidc-loki` to `@oidc-loki/core`).
- oidc-provider dependency stays in server package only -- client package should have zero server-side deps.
