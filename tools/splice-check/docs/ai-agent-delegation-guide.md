# AI Agent Delegation Guide

> **Who this is for:** Developers building AI agents, tool-calling systems, and multi-agent orchestrators that need to access APIs on behalf of users.
>
> **Difficulty:** Intermediate

This guide shows you how to implement secure delegation chains in AI agent systems using OAuth 2.0 Token Exchange ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)). It covers the common pitfalls that lead to chain splicing vulnerabilities and how to avoid them.

---

## Why Agents Need Token Exchange

When an AI agent acts on behalf of a user, it needs credentials. There are three common approaches, ranked from worst to best:

| Approach | Security | Why |
|----------|----------|-----|
| Share the user's credentials | Terrible | Agent has full user access, no audit trail, no revocation |
| Long-lived API keys | Bad | Static secrets, no scope limits, survive credential rotation |
| **Token exchange (delegation)** | **Good** | Scoped, time-limited, auditable, revocable |

Token exchange lets an agent say: "Here's proof that Alice authorized me. Give me a token that says I'm acting on her behalf, with only the permissions I need, that expires soon."

The result is a delegation token:

```json
{
  "sub": "alice",
  "act": { "sub": "my-agent" },
  "scope": "read:documents",
  "aud": "document-api",
  "exp": 1709078400
}
```

This token says: "my-agent is acting for alice, can read documents, only at the document-api, and expires in 30 minutes."

---

## The Token Exchange Flow

Here's the HTTP request your agent makes to the Authorization Server:

```http
POST /oauth2/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOi...        (Alice's token)
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=eyJhbGciOi...          (your agent's token)
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=document-api
&scope=read:documents
&client_id=my-agent
&client_secret=agent-secret
```

The AS validates both tokens, confirms the delegation is authorized, and returns a new token with `act` claim.

---

## Common Mistakes (And How splice-check Catches Them)

### Mistake 1: Not Authenticating Your Agent

Some implementations skip client authentication on the token exchange endpoint — the agent sends tokens without proving its own identity.

**Why it's dangerous:** Any process that obtains a user's token can mint delegation tokens. There's no binding between "who is requesting" and "who the token says is acting."

**How to avoid:** Always include `client_id` and `client_secret` (or use mTLS, private_key_jwt, etc.) in your exchange requests.

**splice-check vector:** `unauthenticated-exchange` — Tests whether your AS accepts exchange requests without client credentials.

### Mistake 2: Passing the Wrong Actor Token

Your agent should present its own token as the `actor_token`. If it presents another agent's token, the resulting delegation token will name the wrong actor.

```
BAD:  subject=Alice, actor=Agent-B's-token, client=My-Agent
      Result: "Agent B acts for Alice" (but My-Agent requested it)

GOOD: subject=Alice, actor=My-Agent's-token, client=My-Agent
      Result: "My-Agent acts for Alice" (correct)
```

**splice-check vector:** `actor-client-mismatch` — Tests whether the AS binds client identity to actor token identity.

### Mistake 3: Requesting More Scope Than You Need

If Alice's token grants `read write delete`, your agent should request only what it needs:

```
BAD:  scope=read write delete  (requesting everything Alice has)
GOOD: scope=read               (requesting only what's needed)
```

A well-configured AS will reject scope escalation — requesting scopes broader than the source token allows.

**splice-check vector:** `scope-escalation` — Tests whether the AS constrains delegated scope.

### Mistake 4: Not Setting an Audience

Without an `audience` parameter, the AS may issue a delegation token valid at any resource server. Always specify where the token will be used:

```
BAD:  (no audience parameter)
      Result: token valid everywhere

GOOD: audience=document-api
      Result: token valid only at document-api
```

**splice-check vector:** `downstream-aud-verification` — Tests whether delegated tokens have constrained `aud` claims.

### Mistake 5: Ignoring Token Lifetime

Your delegation token should expire before the source token. If Alice's token expires in 1 hour, your agent's delegation token should expire sooner (e.g., 30 minutes). This limits the window of exposure if the delegation token is compromised.

**splice-check vector:** `token-lifetime-reduction` — Tests whether delegated token `exp` exceeds the original.

---

## Multi-Agent Chains

In multi-agent systems, agents delegate to sub-agents, creating chains:

```
Alice → Orchestrator → Planner → Executor → API
```

Each hop is a token exchange. The delegation history is recorded in nested `act` claims:

```json
{
  "sub": "alice",
  "act": {
    "sub": "executor",
    "act": {
      "sub": "planner",
      "act": {
        "sub": "orchestrator"
      }
    }
  }
}
```

### Chain Safety Rules

**1. Each hop must narrow or maintain scope — never widen.**

```
Orchestrator: scope=plan,execute,read
Planner:      scope=plan,read         (narrowed)
Executor:     scope=execute,read      (narrowed differently)
```

**2. Each hop must shorten or maintain lifetime — never extend.**

```
Orchestrator: exp=T+3600  (1 hour)
Planner:      exp=T+1800  (30 min)
Executor:     exp=T+900   (15 min)
```

**3. Limit chain depth.** Most real workflows need 3-5 hops. Set a maximum.

**4. Watch for cycles.** If Agent A delegates to Agent B, which delegates back to Agent A, you have a circular chain. The AS should reject this.

**splice-check vectors:** `chain-depth-exhaustion`, `circular-delegation`, `act-nesting-integrity`

---

## Implementation Checklist

Use this checklist when building agent delegation:

### Your Agent Should:

- [ ] **Authenticate on every exchange request** — Include client credentials
- [ ] **Use its own token as actor_token** — Never use another agent's token
- [ ] **Request minimum scope** — Only scopes needed for the current operation
- [ ] **Specify audience** — Name the target resource server
- [ ] **Request short lifetimes** — Match the token lifetime to the operation duration
- [ ] **Verify the `act` claim** — Confirm the delegation token names your agent as actor
- [ ] **Handle revocation** — Check token validity before long-running operations
- [ ] **Respect `may_act`** — If the user's token includes `may_act`, your agent must be listed

### Your AS Should:

- [ ] **Require client authentication** on the token exchange endpoint
- [ ] **Cross-validate subject and actor** — Verify the relationship between tokens
- [ ] **Bind client identity to actor** — Reject mismatches
- [ ] **Constrain output `aud`** — Set audience on delegated tokens
- [ ] **Include `act` claim** — Mark delegation tokens as delegation (not impersonation)
- [ ] **Enforce scope reduction** — Delegated scope must not exceed source
- [ ] **Enforce lifetime reduction** — Delegated `exp` must not exceed source
- [ ] **Limit chain depth** — Reject exchanges that would exceed maximum (3-5 hops)
- [ ] **Detect circular chains** — Reject A→B→A delegation cycles
- [ ] **Propagate revocation** — Revoking a source token invalidates derived tokens

---

## Testing Your Setup

Run splice-check against your AS to verify it handles delegation safely:

```bash
# Install
cd tools/splice-check
npm install && npm run build

# Configure (see README for full config reference)
cat > my-as.toml << 'EOF'
[target]
token_endpoint = "https://your-as.example.com/oauth2/token"
jwks_endpoint = "https://your-as.example.com/oauth2/jwks"
issuer = "https://your-as.example.com"

[target.auth]
method = "client_secret_post"

[clients.alice]
client_id = "alice-app"
client_secret = "${ALICE_SECRET}"
scope = "openid profile"

[clients.agent-a]
client_id = "agent-a-client"
client_secret = "${AGENT_A_SECRET}"

[clients.agent-n]
client_id = "agent-n-client"
client_secret = "${AGENT_N_SECRET}"
EOF

# Run all 28 attack vectors
npx splice-check --config my-as.toml

# JSON output for CI/CD
npx splice-check --config my-as.toml --format json > results.json
```

The three clients simulate your delegation scenario:
- **alice** — The human user who grants initial authorization
- **agent-a** — A legitimate agent authorized to act on behalf of Alice
- **agent-n** — A malicious agent attempting to splice into Alice's delegation chain

---

## Quick Reference: Token Exchange Parameters

| Parameter | Required | Your Agent Should Set |
|-----------|----------|---------------------|
| `grant_type` | Yes | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | Yes | The user's access token |
| `subject_token_type` | Yes | `urn:ietf:params:oauth:token-type:access_token` |
| `actor_token` | For delegation | Your agent's own access token |
| `actor_token_type` | With actor_token | `urn:ietf:params:oauth:token-type:access_token` |
| `audience` | Recommended | Target resource server identifier |
| `scope` | Recommended | Minimum required scopes |
| `resource` | Optional | Target resource URI |
| `requested_token_type` | Optional | Defaults to access_token |

---

## Specifications

- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) — The token exchange protocol
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/rfc9700/) — Current security best practices (January 2025)
- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) — JWT format and claims
- [RFC 7009 — Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009) — Revoking tokens
- [RFC 6749 — OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) — The OAuth framework

---

## Further Reading

- [What Is Chain Splicing?](what-is-chain-splicing.md) — Non-technical overview of the vulnerability
- [Attack Vectors Reference](attack-vectors.md) — Full technical details for all 28 tests
- [Securing Delegation in Agentic Architectures](agentic-delegation-security.md) — Architecture-level design patterns
- [splice-check README](../README.md) — Configuration and usage reference

---

*splice-check is part of the [oidc-loki](https://github.com/oidc-loki/oidc-loki) project. For authorized security testing only.*
