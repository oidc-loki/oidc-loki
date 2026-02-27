# Plan 001: splice-check CLI (Phase B)

**Status:** Draft
**Priority:** P0
**Depends on:** None
**Blocks:** Plan 002

---

## Goal

Ship a standalone CLI tool (`splice-check`) that validates any OAuth 2.0 Authorization Server's resistance to delegation chain splicing attacks. Lives in the oidc-loki monorepo but runs independently.

## Architecture Decisions

### Where it lives

```
oidc-loki/
├── src/                    # Existing server-side code (untouched)
├── tools/
│   └── splice-check/
│       ├── package.json    # Own deps, own bin entry
│       ├── tsconfig.json   # Extends root tsconfig
│       ├── src/
│       │   ├── cli.ts          # Entry point (commander or yargs)
│       │   ├── runner.ts       # Test orchestrator
│       │   ├── config.ts       # Config loader + types
│       │   ├── client.ts       # OAuth/token exchange HTTP client
│       │   ├── reporter.ts     # Output formatting (table, JSON, markdown)
│       │   └── tests/
│       │       ├── types.ts        # AttackTest interface
│       │       ├── index.ts        # Test registry
│       │       ├── valid-delegation.ts
│       │       ├── basic-splice.ts
│       │       ├── aud-sub-binding.ts
│       │       ├── upstream-splice.ts
│       │       ├── multi-audience.ts
│       │       ├── missing-aud.ts
│       │       ├── may-act-enforcement.ts
│       │       ├── refresh-bypass.ts
│       │       └── revocation-propagation.ts
│       └── tests/
│           └── *.test.ts   # Unit tests for the tool itself
```

**Why not a full monorepo with packages/ yet:** Phase B should be minimal. A `tools/` directory avoids the pnpm-workspace / Turborepo overhead. Phase C is when we restructure into packages.

### The test interface

```typescript
// tools/splice-check/src/tests/types.ts

export interface AttackTest {
  id: string;
  name: string;
  description: string;
  spec: string;                    // e.g., "RFC 8693 Section 2.1"
  severity: "critical" | "high" | "medium" | "low";

  /** Obtain legitimate tokens needed for this test */
  setup(ctx: TestContext): Promise<SetupResult>;

  /** Craft and send the attack request */
  attack(ctx: TestContext, setup: SetupResult): Promise<AttackResponse>;

  /** Determine if the AS responded correctly */
  verify(response: AttackResponse): TestVerdict;
}

export interface TestContext {
  config: TargetConfig;
  client: OAuthClient;       // HTTP client for token endpoint
  log: (msg: string) => void;
}

export interface SetupResult {
  tokens: Record<string, string>;  // Named tokens obtained during setup
  metadata?: Record<string, unknown>;
}

export interface AttackResponse {
  status: number;
  body: unknown;
  headers: Record<string, string>;
  durationMs: number;
}

export type TestVerdict =
  | { passed: true; reason: string }
  | { passed: false; reason: string; expected: string; actual: string }
  | { skipped: true; reason: string };
```

### Config format

```toml
# splice-check.toml

[target]
token_endpoint = "https://localhost:9443/oauth2/token"
jwks_endpoint  = "https://localhost:9443/oauth2/jwks"
issuer         = "https://localhost:9443/oauth2/token"

[target.auth]
# How test clients authenticate to the AS
method = "client_secret_post"  # or client_secret_basic, private_key_jwt

# Clients that the test suite will use
# These must be pre-provisioned on the AS with appropriate permissions
[clients.alice]
# The "victim" user -- holds the subject_token
client_id     = "alice-app"
client_secret = "..."
grant_type    = "client_credentials"  # simplest setup
scope         = "openid profile"

[clients.agent-a]
# Legitimate agent in Chain 1
client_id     = "agent-a"
client_secret = "..."

[clients.agent-n]
# The attacker agent (separate chain)
client_id     = "agent-n"
client_secret = "..."

[output]
format = "table"  # table | json | markdown
verbose = false
```

### Test implementations (example)

```typescript
// tools/splice-check/src/tests/basic-splice.ts

import type { AttackTest } from "./types.js";

export const basicSplice: AttackTest = {
  id: "basic-splice",
  name: "Basic Chain Splice",
  description: "Presents subject_token from Chain 1 with actor_token from Chain 2",
  spec: "RFC 8693 Section 2.1",
  severity: "critical",

  async setup(ctx) {
    // 1. Get a token for Alice via agent-a (Chain 1)
    const aliceToken = await ctx.client.clientCredentials("alice");

    // 2. Exchange Alice's token for one scoped to agent-a
    const chain1Token = await ctx.client.tokenExchange({
      subject_token: aliceToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      audience: "agent-a",
    });

    // 3. Get agent-n's own credential (Chain 2)
    const agentNToken = await ctx.client.clientCredentials("agent-n");

    return {
      tokens: {
        subjectToken: chain1Token,  // From Chain 1
        actorToken: agentNToken,    // From Chain 2
      },
    };
  },

  async attack(ctx, setup) {
    // Present subject_token from Chain 1 with actor_token from Chain 2
    return ctx.client.tokenExchange({
      subject_token: setup.tokens.subjectToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      actor_token: setup.tokens.actorToken,
      actor_token_type: "urn:ietf:params:oauth:token-type:access_token",
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    });
  },

  verify(response) {
    if (response.status >= 400) {
      return { passed: true, reason: `AS rejected with ${response.status}` };
    }
    return {
      passed: false,
      reason: "AS accepted spliced token pair",
      expected: "HTTP 400 (invalid_grant or invalid_request)",
      actual: `HTTP ${response.status} with valid token`,
    };
  },
};
```

## Implementation Steps

### Step 1: Scaffold
- [ ] Create `tools/splice-check/` directory structure
- [ ] Set up `package.json` with bin entry, deps (commander, jose, toml)
- [ ] Set up `tsconfig.json` extending root config
- [ ] Create CLI entry point with `--config` flag

### Step 2: OAuth client
- [ ] HTTP client wrapper for token endpoint (fetch-based)
- [ ] Support client_credentials grant
- [ ] Support token exchange grant (RFC 8693 parameters)
- [ ] Support client_secret_post and client_secret_basic auth

### Step 3: Test framework
- [ ] Define `AttackTest` interface
- [ ] Build test runner that executes setup -> attack -> verify
- [ ] Build reporter (table output for terminal, JSON for CI)

### Step 4: Implement tests
- [ ] `valid-delegation` -- baseline: proper exchange should succeed
- [ ] `basic-splice` -- core attack: mismatched subject/actor tokens
- [ ] `aud-sub-binding` -- actor_token.sub vs subject_token.aud mismatch
- [ ] `upstream-splice` -- agent requests re-delegation token for unauthorized downstream
- [ ] `multi-audience` -- subject_token with multi-valued aud array
- [ ] `missing-aud` -- subject_token with no aud claim
- [ ] `may-act-enforcement` -- actor not listed in may_act
- [ ] `refresh-bypass` -- refresh delegated token after consent revocation
- [ ] `revocation-propagation` -- use downstream token after upstream revocation

### Step 5: Local testing
- [ ] Docker Compose file with WSO2 IS
- [ ] Setup script to provision test clients and delegation policies
- [ ] Example config file for local WSO2

### Step 6: Documentation
- [ ] README with usage, config reference, test descriptions
- [ ] Setup guide for WSO2
- [ ] Setup guide for Keycloak (once SPI exists)

## Dependencies

- `commander` or `yargs` -- CLI parsing
- `jose` -- JWT decoding (shared with main oidc-loki)
- `@iarna/toml` or `smol-toml` -- config parsing
- `chalk` -- terminal formatting (optional)

## Success Criteria

- `npx splice-check --config local-wso2.toml` runs all 9 tests against a WSO2 instance
- Output is clear, actionable, and includes pass/fail/skip with reasons
- JSON output mode works for CI integration
- No AS-specific code in the test runner -- all config-driven
