# Plan 005: Deferred Architecture Suggestions (Gemini)

**Status:** Tracked for Phase C
**Priority:** P2
**Depends on:** Plan 002

---

## Purpose

Gemini proposed several architecture decisions during the Phase B/C brainstorm that were deferred for simplicity but should be revisited when Plan 002 (Phase C) begins. Tracking them here so nothing gets lost.

## Deferred Items

### 1. Generic AttackPlugin interface

**Gemini's proposal:** `AttackPlugin<TConfig, TResult extends AttackResult>` with generic type parameters so each plugin can define its own config shape and result type.

**Why deferred:** Plan 001 uses a concrete `AttackTest` interface with fixed types. Generics add complexity before we know the shape of the second or third client-side test suite.

**When to revisit:** When adding a second client-side test suite beyond splice-check (e.g., a DPoP conformance suite or a PKCE downgrade client-side test). If the concrete types feel constraining at that point, introduce the generics.

### 2. Full pnpm workspace with 5 packages

**Gemini's proposal:**
```
packages/
├── oidc-loki/           # Server
├── splice-check-cli/    # Client CLI
├── splice-check-plugins/# Client plugins
├── common-models/       # Shared types
└── common-ledger/       # Shared reporting
```

**Why deferred:** Five packages is overhead for a single CLI tool. Plan 001 uses `tools/splice-check/` as a subdirectory with its own package.json.

**When to revisit:** Plan 002 restructures into packages, but likely 4 not 5 -- folding `splice-check-plugins` into `client` and `common-ledger` into `core`. Gemini's separation of plugins from CLI runner is worth preserving as a directory-level boundary even if not a package boundary.

### 3. Separate common-ledger package

**Gemini's proposal:** A dedicated package for `LedgerWriter` interface with `SqliteLedger` and `JsonFileLedger` implementations shared across server and client.

**Why deferred:** Plan 001's reporter is self-contained (table, JSON, markdown output). The existing server-side ledger lives in `src/ledger/`.

**When to revisit:** During Plan 002 when unifying the ledger. The abstraction (`LedgerWriter` interface) is correct -- the question is whether it needs its own package or lives in `packages/core/`.

### 4. Discriminated union for LedgerEntry

**Gemini's proposal:**
```typescript
type LedgerEntry = MischiefEntry | AttackLogEntry;
// Each has a `type` field: "mischief" | "attack"
```

**Why deferred:** Plan 001 doesn't share a ledger with the server. It outputs its own reports.

**When to revisit:** Plan 002 Step 1 (Define shared core). This is the right design for the unified ledger. Adopt it.

### 5. Detailed AttackResponse with timings

**Gemini's proposal:**
```typescript
interface AttackResponse {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: any;
  timings: { total: number };
}
```

**Current Plan 001 version:**
```typescript
interface AttackResponse {
  status: number;
  body: unknown;
  headers: Record<string, string>;
  durationMs: number;
}
```

**Delta:** Gemini nests timings in an object (extensible for future `dns`, `tls`, `ttfb` breakdowns). Plan 001 uses a flat `durationMs`.

**When to revisit:** If we add performance testing or latency analysis to the attack suite, adopt the nested timings object.

### 6. TargetClientConfig with auth method flexibility

**Gemini's proposal:** Each client in the config specifies its own `token_endpoint_auth_method` and optionally a `privateKey` (JWK) for `private_key_jwt`.

**Why deferred:** Plan 001 uses a global `[target.auth]` method. Per-client auth methods add config complexity before we need it.

**When to revisit:** When testing against an AS that requires different auth methods for different clients (e.g., agent-a uses `client_secret_post`, agent-n uses `private_key_jwt`). Real-world WSO2 and Keycloak deployments may require this.

### 7. Plugin `run()` orchestrator method

**Gemini's proposal:** `AttackPlugin` includes a `run(config)` method that orchestrates `setup` -> `attack` -> `verify` as a convenience.

**Why deferred:** Plan 001 puts this orchestration in the runner, not the plugin. Each plugin only defines the three phases; the runner calls them in sequence.

**When to revisit:** If plugins need to control their own orchestration (e.g., a test that requires multiple attack rounds or iterative probing), the `run()` method gives them that flexibility. Consider during Phase C.

---

## How to use this document

When starting Plan 002, review each item above and decide: adopt now, defer further, or discard. Mark each with a decision and rationale.
