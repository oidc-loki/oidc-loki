# splice-check

> Validate OAuth 2.0 Authorization Server resistance to delegation chain splicing attacks.

**Who this is for:** Platform engineers, DevOps, and security teams who need to test whether their Authorization Server correctly validates [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) token exchange requests.

**Difficulty:** Intermediate

splice-check sends 28 attack vectors against your AS's token exchange endpoint, covering chain splicing, input validation, output validation, delegation chain integrity, and operational security. It reports which attacks your AS correctly rejected and which it failed to catch.

## Quick Start

### 1. Install

```bash
cd tools/splice-check
npm install
npm run build
```

### 2. Configure

Create a TOML config file describing your AS:

```toml
# my-as.toml

[target]
token_endpoint = "https://your-as.example.com/oauth2/token"
jwks_endpoint = "https://your-as.example.com/oauth2/jwks"
issuer = "https://your-as.example.com"
revocation_endpoint = "https://your-as.example.com/oauth2/revoke"       # optional
introspection_endpoint = "https://your-as.example.com/oauth2/introspect" # optional

[target.auth]
method = "client_secret_post"  # or "client_secret_basic"

# Three clients are required: a "user" (alice) and two "agents"
[clients.alice]
client_id = "alice-app"
client_secret = "${ALICE_SECRET}"   # env vars supported
scope = "openid profile"

[clients.agent-a]
client_id = "agent-a-client"
client_secret = "${AGENT_A_SECRET}"

[clients.agent-n]
client_id = "agent-n-client"
client_secret = "${AGENT_N_SECRET}"

[output]
format = "table"    # table | json | markdown
verbose = false
```

**Why three clients?** Chain splicing attacks require tokens from different authorization chains. `alice` represents a human user. `agent-a` is a legitimate delegate. `agent-n` is an unauthorized agent that attempts to splice into Alice's delegation chain.

### 3. Run

```bash
# Run all 28 tests
npx splice-check --config my-as.toml

# Verbose mode (shows setup/attack logs)
npx splice-check --config my-as.toml --verbose

# Run specific tests
npx splice-check --config my-as.toml --test basic-splice --test aud-sub-binding

# JSON output for CI/CD integration
npx splice-check --config my-as.toml --format json

# Markdown report
npx splice-check --config my-as.toml --format markdown > report.md

# List all available tests
npx splice-check --list
```

### 4. Interpret Results

```
  splice-check v0.1.0
  Target: https://your-as.example.com/oauth2/token
  Tests:  28

  Running valid-delegation... PASS
  Running basic-splice...     PASS
  Running actor-client-mismatch... PASS
  Running issuer-validation... FAIL
  Running circular-delegation... SKIP

  ┌─────────────────────────────────┬──────────┬──────────┐
  │ Test                            │ Severity │ Result   │
  ├─────────────────────────────────┼──────────┼──────────┤
  │ valid-delegation                │ critical │ PASS     │
  │ basic-splice                    │ critical │ PASS     │
  │ issuer-validation               │ critical │ FAIL     │
  │ circular-delegation             │ high     │ SKIP     │
  └─────────────────────────────────┴──────────┴──────────┘

  Summary: 20 passed, 3 failed, 5 skipped (28 total)
```

- **PASS** — Your AS correctly handled this attack vector
- **FAIL** — Your AS is vulnerable. See the failure reason for details
- **SKIP** — Test was inconclusive (e.g., AS returned 401 auth error, 429 rate limit, or 500 server error). This is not a pass or fail — investigate the underlying issue

**Exit codes:**
- `0` — All tests passed (or skipped)
- `1` — One or more tests failed (vulnerability detected)
- `2` — Configuration error

## The 28 Attack Vectors

### Baseline
| ID | Severity | What It Tests |
|----|----------|---------------|
| `valid-delegation` | critical | Legitimate exchange (Alice → Agent A). Must pass for other tests to be meaningful. |

### Core Splice Attacks
| ID | Severity | What It Tests |
|----|----------|---------------|
| `basic-splice` | critical | Subject token from Chain 1 + actor token from Chain 2. Classic splice. |
| `actor-client-mismatch` | critical | Agent N authenticates as itself but presents Agent A's token as actor. |
| `aud-sub-binding` | critical | Subject token's `aud` targets Agent A, but Agent N presents it. |
| `upstream-splice` | high | Re-delegation of a legitimate delegated token by an unauthorized agent. |
| `subject-actor-swap` | high | Swaps subject and actor tokens, inverting the delegation relationship. |

### Input Validation
| ID | Severity | What It Tests |
|----|----------|---------------|
| `token-type-mismatch` | high | Declares access_token as id_token type. AS must validate type. |
| `unauthenticated-exchange` | critical | Token exchange without client authentication. |
| `token-type-escalation` | high | Requests refresh_token from access_token exchange. |
| `audience-targeting` | high | Targets unauthorized audience in exchange request. |
| `act-claim-stripping` | high | Re-exchanges delegation token to strip the `act` claim. |
| `resource-abuse` | high | Targets internal service URI via `resource` parameter. |

### Token Forgery
| ID | Severity | What It Tests |
|----|----------|---------------|
| `issuer-validation` | critical | Fabricated JWT from fake issuer submitted as subject_token. |
| `expired-token-exchange` | high | Expired JWT submitted as subject_token. |

### Edge Cases
| ID | Severity | What It Tests |
|----|----------|---------------|
| `multi-audience` | high | Subject token with multi-valued `aud` array enables permissive matching. |
| `missing-aud` | high | Subject token without `aud` claim — AS cannot bind audience. |
| `may-act-enforcement` | high | Verifies AS enforces `may_act` claim to restrict authorized actors. |
| `scope-escalation` | high | Requests broader scope than subject_token allows. |
| `delegation-impersonation-confusion` | high | Verifies result has `act` claim (delegation not impersonation). |

### Output Validation
| ID | Severity | What It Tests |
|----|----------|---------------|
| `issued-token-type-validation` | medium | Response must include required `issued_token_type` field. |
| `downstream-aud-verification` | high | Delegated token must have constrained `aud` claim. |
| `token-lifetime-reduction` | medium | Delegated token `exp` must not exceed original. |
| `act-sub-verification` | high | `act.sub` in result must match the intended actor. |
| `act-nesting-integrity` | high | Multi-hop `act` chain must be intact with no non-identity claim leakage. |

### Delegation Chain Integrity
| ID | Severity | What It Tests |
|----|----------|---------------|
| `circular-delegation` | high | Creates A→N→A cycle. AS must detect and reject circular chains. |
| `chain-depth-exhaustion` | high | 5 successive delegation hops. AS must enforce max depth. |

### Operational Security
| ID | Severity | What It Tests |
|----|----------|---------------|
| `refresh-bypass` | high | Refresh after revocation of original token. |
| `revocation-propagation` | high | Revoking subject_token must invalidate downstream delegated tokens. |

## CI/CD Integration

splice-check exits with code 1 when vulnerabilities are detected, making it suitable for CI pipelines:

```yaml
# GitHub Actions example
- name: Token Exchange Security Check
  run: |
    npx splice-check --config my-as.toml --format json > splice-check-results.json
    npx splice-check --config my-as.toml --format markdown > splice-check-report.md
  continue-on-error: false
```

## Configuration Reference

### `[target]`

| Field | Required | Description |
|-------|----------|-------------|
| `token_endpoint` | Yes | Token exchange endpoint URL |
| `jwks_endpoint` | Yes | JWKS endpoint URL |
| `issuer` | Yes | Expected `iss` value in tokens |
| `revocation_endpoint` | No | Token revocation endpoint (RFC 7009) |
| `introspection_endpoint` | No | Token introspection endpoint (RFC 7662) |
| `timeout` | No | Request timeout in ms (default: 30000) |

### `[target.auth]`

| Field | Required | Description |
|-------|----------|-------------|
| `method` | Yes | `client_secret_post` or `client_secret_basic` |

### `[clients.<name>]`

Three clients are required: `alice`, `agent-a`, and `agent-n`.

| Field | Required | Description |
|-------|----------|-------------|
| `client_id` | Yes | OAuth client ID |
| `client_secret` | Yes | OAuth client secret (supports `${ENV_VAR}`) |
| `scope` | No | Scopes to request |
| `grant_type` | No | Grant type for initial tokens (default: `client_credentials`) |

### `[output]`

| Field | Required | Description |
|-------|----------|-------------|
| `format` | No | `table` (default), `json`, or `markdown` |
| `verbose` | No | Include setup/attack phase logs (default: `false`) |

## Specifications Tested

- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) (Sections 1.1, 2.1, 2.2, 2.2.1, 4.1, 4.4, 5)
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/rfc9700/) (Jan 2025)
- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) (Section 4.1.3)
- [RFC 7009 — OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
- [RFC 7662 — OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 6749 — OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749) (Section 6)

## Further Reading

- [What Is Delegation Chain Splicing?](docs/what-is-chain-splicing.md) — Beginner-friendly explainer
- [Attack Vectors Reference](docs/attack-vectors.md) — Full technical details for all 28 vectors
- [Securing Delegation in Agentic Architectures](docs/agentic-delegation-security.md) — For identity architects
- [RFC 8693 Gap Analysis](docs/rfc8693-gap-analysis.md) — For standards authors and IETF participants
- [Security Posture Assessment Guide](docs/security-posture-assessment.md) — For CISOs and compliance teams
- [AI Agent Delegation Guide](docs/ai-agent-delegation-guide.md) — For developers building AI agents

## Development

```bash
npm install
npm test          # run test suite (274 tests)
npm run lint      # biome check
npm run build     # tsc compile
```

## License

Part of the [oidc-loki](https://github.com/oidc-loki/oidc-loki) project.
