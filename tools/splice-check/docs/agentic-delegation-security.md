# Securing Delegation in Agentic Architectures

> **Who this is for:** Identity architects, platform security engineers, and zero trust practitioners designing delegation models for microservices and AI agent systems.
>
> **Difficulty:** Advanced

This document examines how token exchange delegation — and its vulnerabilities — interact with agentic architectures: systems where autonomous software agents act on behalf of users, chain operations through multiple services, and make independent decisions about resource access.

---

## The Agentic Delegation Problem

Traditional OAuth delegation assumes a simple model: a user authorizes an application, the application accesses resources. The delegation chain is short (usually one hop) and human-initiated.

Agentic architectures break these assumptions:

| Traditional OAuth | Agentic Architecture |
|-------------------|---------------------|
| Human initiates every action | Agents initiate actions autonomously |
| 1-2 hop delegation chains | 3-10+ hop chains (agent → sub-agent → tool → API) |
| Static scopes requested at auth time | Dynamic scope requirements discovered at runtime |
| Single resource server target | Multiple resource servers across trust boundaries |
| Short-lived sessions | Long-running autonomous workflows |

The result: **delegation chains become the primary attack surface.** An agent compromised at any point in a multi-hop chain can splice its way into unrelated chains, escalate privileges, or persist access beyond revocation.

### A Concrete Scenario

Consider an AI coding assistant architecture:

```
User (Alice)
  └─→ Orchestrator Agent
        ├─→ Code Analysis Agent
        │     └─→ Repository API (GitHub)
        ├─→ Security Scanning Agent
        │     └─→ Vulnerability Database API
        └─→ Deployment Agent
              ├─→ Container Registry
              └─→ Kubernetes API
```

Each arrow is a delegation hop. Alice authorized the Orchestrator. The Orchestrator delegates to specialized agents. Each agent accesses specific APIs. That's 3-4 hops with 5+ resource servers — and each hop requires a token exchange.

If the Security Scanning Agent is compromised, can it:

1. **Splice into the Deployment Agent's chain** to push malicious containers?
2. **Escalate its read-only scan scope** to write access?
3. **Target the Kubernetes API** even though Alice never authorized it for that agent?
4. **Persist access** after Alice revokes the Orchestrator's token?

These are exactly the attacks splice-check tests for. The difference in agentic systems is that attack surface scales with chain depth and agent count.

---

## Threat Model: Agent-Specific Risks

### 1. Lateral Movement via Chain Splicing

**Traditional risk:** Compromised web app accesses user's email.
**Agentic risk:** Compromised sub-agent splices tokens from parallel chains to access unrelated services.

In the architecture above, the Code Analysis Agent holds a token for Repository API access. The Security Scanning Agent holds a token for the Vulnerability Database. If the AS doesn't cross-validate subject and actor tokens, a compromised Scanning Agent can present:

- **subject_token:** Alice's original token (stolen from shared context)
- **actor_token:** Its own token

And receive a delegation token saying "Scanning Agent acts for Alice" with Repository API access — a chain that was never authorized.

**Relevant splice-check vectors:**
- `basic-splice` — Cross-chain subject + actor combination
- `actor-client-mismatch` — Agent presents another agent's actor token
- `aud-sub-binding` — Subject token's audience doesn't match presenting agent
- `upstream-splice` — Re-delegation of another agent's delegated token

### 2. Scope Creep Through Multi-Hop Chains

Each delegation hop should narrow scope. In practice, agentic systems often request the union of scopes they might need:

```
Hop 1: Alice → Orchestrator    scope: "read write deploy scan"
Hop 2: Orchestrator → Scanner  scope: "read scan"
Hop 3: Scanner → Sub-scanner   scope: "read scan" (should be narrower)
```

If the AS doesn't enforce monotonic scope reduction, hop 3 could request `"read write scan"` — escalating beyond what the Orchestrator granted to the Scanner.

**Relevant splice-check vectors:**
- `scope-escalation` — Requests broader scope than source token
- `token-type-escalation` — Converts access token to refresh token
- `resource-abuse` — Targets unauthorized resource URIs

### 3. Delegation Depth Exhaustion

AI agent systems create deeper chains than traditional OAuth anticipated. An orchestrator that spawns sub-agents, which spawn tool-calling agents, which call APIs, can easily reach 5-10 delegation hops. Each hop adds an `act` claim nesting level.

Without depth limits:
- Tokens grow unboundedly (each `act` nesting adds ~100 bytes of JWT payload)
- Parser complexity increases (deeply nested JSON)
- Audit trail becomes unreadable
- DoS via intentional depth inflation becomes possible

**Relevant splice-check vectors:**
- `chain-depth-exhaustion` — 5 successive delegation hops
- `circular-delegation` — A→N→A cycle detection
- `act-nesting-integrity` — Validates nested `act` claims contain only identity data

### 4. Identity Confusion at Scale

When dozens of agents exchange tokens, the distinction between **delegation** (agent acts on behalf of user) and **impersonation** (agent becomes the user) is critical. A token without an `act` claim looks like impersonation — downstream services cannot distinguish "this is Alice" from "this is an agent acting for Alice."

In agentic systems, this confusion enables:
- **Audit trail destruction** — No record of which agent performed an action
- **Policy bypass** — Rate limits or access policies applied to Alice rather than the agent
- **Accountability gaps** — Impossible to attribute actions to specific agents

**Relevant splice-check vectors:**
- `delegation-impersonation-confusion` — Verifies `act` claim presence
- `act-claim-stripping` — Detects `act` removal during re-exchange
- `act-sub-verification` — Confirms `act.sub` matches the actual actor

---

## Design Patterns for Secure Agentic Delegation

### Pattern 1: Audience-Constrained Delegation

Every delegated token should name its intended consumer in the `aud` claim. This prevents lateral movement: a token issued for the Repository API cannot be replayed against the Kubernetes API.

```
Token for Code Analysis Agent:
{
  "sub": "alice",
  "aud": "repository-api",
  "act": { "sub": "code-analysis-agent" },
  "scope": "repo:read"
}
```

**Enforcement:** The AS must set `aud` on every delegated token. Resource servers must reject tokens where `aud` doesn't match their identifier.

**splice-check coverage:** `downstream-aud-verification`, `audience-targeting`, `multi-audience`

### Pattern 2: may_act Pre-Authorization

Instead of trusting any agent to request delegation, encode authorized delegation relationships in the token itself using the `may_act` claim ([RFC 8693 Section 4.4](https://datatracker.ietf.org/doc/html/rfc8693#section-4.4)):

```
Alice's token for the Orchestrator:
{
  "sub": "alice",
  "may_act": {
    "sub": "orchestrator-agent"
  }
}

Orchestrator's token for Code Analysis:
{
  "sub": "orchestrator-agent",
  "may_act": {
    "sub": "code-analysis-agent"
  }
}
```

The AS checks `may_act` before issuing delegation tokens, creating an explicit authorization graph rather than implicit trust.

**splice-check coverage:** `may-act-enforcement`

### Pattern 3: Monotonic Scope and Lifetime Reduction

Each delegation hop must produce a token with equal or narrower scope and equal or shorter lifetime than its source:

```
Hop 0: Alice         scope: "read write"   exp: T+3600
Hop 1: Orchestrator  scope: "read write"   exp: T+1800  (≤ source)
Hop 2: Scanner       scope: "read"         exp: T+900   (≤ source)
Hop 3: Sub-scanner   scope: "read"         exp: T+300   (≤ source)
```

This guarantees that delegation cannot grant more access than the delegator holds, and that deeper chains have shorter windows.

**splice-check coverage:** `scope-escalation`, `token-lifetime-reduction`

### Pattern 4: Chain Depth Budgeting

Set an explicit maximum delegation depth. For most agentic architectures, 3-5 hops covers realistic use cases. Each delegation hop should decrement a "remaining depth" counter:

```
Hop 0: Alice → Orchestrator      depth_remaining: 3
Hop 1: Orchestrator → Scanner    depth_remaining: 2
Hop 2: Scanner → Sub-scanner     depth_remaining: 1
Hop 3: Sub-scanner → Tool        depth_remaining: 0 (no further delegation)
```

The AS enforces this by counting `act` nesting levels and rejecting exchanges that would exceed the limit.

**splice-check coverage:** `chain-depth-exhaustion`

### Pattern 5: Revocation Cascades

When Alice revokes the Orchestrator's token, all downstream delegation tokens must also become invalid. This requires the AS to track token derivation relationships and propagate revocation ([RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)):

```
Revoke(Alice → Orchestrator)
  ├─→ Invalidate(Orchestrator → Code Analysis)
  ├─→ Invalidate(Orchestrator → Scanner)
  │     └─→ Invalidate(Scanner → Sub-scanner)
  └─→ Invalidate(Orchestrator → Deployer)
```

Without cascade revocation, a compromised agent retains access even after the user revokes authorization — the agent's derived token remains valid until expiry.

**splice-check coverage:** `revocation-propagation`, `refresh-bypass`

---

## Implementation Checklist

For identity architects designing delegation for agentic systems:

| # | Control | Test Coverage |
|---|---------|---------------|
| 1 | Cross-validate subject and actor tokens on every exchange | `basic-splice`, `actor-client-mismatch`, `aud-sub-binding` |
| 2 | Bind authenticated client identity to actor token subject | `actor-client-mismatch` |
| 3 | Require client authentication on the exchange endpoint | `unauthenticated-exchange` |
| 4 | Set constrained `aud` on every delegated token | `downstream-aud-verification` |
| 5 | Include `act` claim in all delegation tokens | `delegation-impersonation-confusion` |
| 6 | Preserve `act` chains during re-exchange | `act-claim-stripping`, `act-nesting-integrity` |
| 7 | Enforce monotonic scope reduction | `scope-escalation` |
| 8 | Enforce monotonic lifetime reduction | `token-lifetime-reduction` |
| 9 | Set maximum delegation depth (3-5 recommended) | `chain-depth-exhaustion` |
| 10 | Detect and reject circular delegation chains | `circular-delegation` |
| 11 | Enforce `may_act` when present | `may-act-enforcement` |
| 12 | Propagate revocation through delegation chains | `revocation-propagation`, `refresh-bypass` |
| 13 | Validate issuer on all incoming tokens | `issuer-validation` |
| 14 | Reject expired tokens in exchange requests | `expired-token-exchange` |

Run splice-check against your AS to verify these controls:

```bash
npx splice-check --config your-as.toml --format json
```

---

## Zero Trust Alignment

Agentic delegation maps directly to zero trust principles:

| Zero Trust Principle | Delegation Implementation |
|---------------------|--------------------------|
| Never trust, always verify | Cross-validate subject and actor on every exchange |
| Least privilege | Monotonic scope and lifetime reduction per hop |
| Assume breach | Chain depth limits + revocation cascades contain blast radius |
| Verify explicitly | `may_act` pre-authorization + audience constraints |
| Microsegmentation | Per-agent, per-resource audience targeting |

---

## Further Reading

- [What Is Chain Splicing?](what-is-chain-splicing.md) — Non-technical overview
- [Attack Vectors Reference](attack-vectors.md) — Full technical details for all 28 tests
- [AI Agent Delegation Guide](ai-agent-delegation-guide.md) — Practical implementation guide for developers
- [RFC 8693 Gap Analysis](rfc8693-gap-analysis.md) — Specification-level root causes
- [Security Posture Assessment](security-posture-assessment.md) — Compliance and reporting

---

*splice-check is part of the [oidc-loki](https://github.com/oidc-loki/oidc-loki) project. For authorized security testing only.*
