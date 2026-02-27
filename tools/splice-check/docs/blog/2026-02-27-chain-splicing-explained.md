---
title: "Delegation Chain Splicing: The OAuth Attack Your Authorization Server Probably Doesn't Catch"
published: true
tags: security, oauth, token-exchange, delegation, ai-agents
cover_image:
---

## The Setup

OAuth 2.0 Token Exchange ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)) lets services act on behalf of users. It's the standard mechanism for service-to-service delegation — and it's increasingly critical as AI agents need to call APIs on your behalf.

The flow is straightforward:

1. Alice logs in and gets an access token
2. Agent A needs to call an API on Alice's behalf
3. Agent A asks the Authorization Server: "Here's Alice's token (subject) and my token (actor). Give me a delegation token."
4. The AS validates both tokens and issues a new one with an `act` claim: "Agent A is acting for Alice"

Simple. Well-specified. And vulnerable to a class of attacks we call **delegation chain splicing**.

## The Vulnerability

Here's the problem. When the AS processes a token exchange, it validates each token independently:

- Is the subject token valid? **Check.**
- Is the actor token valid? **Check.**
- Issue the delegation token.

But what if those tokens come from **completely unrelated authorization chains?**

```
Chain 1 (legitimate):    Alice ──→ Agent A
Chain 2 (attacker's):    Bob   ──→ Agent N (compromised)

Agent N takes Alice's token from Chain 1
  and presents it with its own token:

  subject_token = Alice's token (stolen/leaked)
  actor_token   = Agent N's own token
```

The AS checks both tokens. Both are individually valid. It issues a delegation token: **"Agent N is acting for Alice."**

Agent N now holds a forged delegation that Alice never authorized. Two unrelated trust chains — spliced into one.

## Why Does RFC 8693 Allow This?

We analyzed RFC 8693 section by section (full analysis: [RFC 8693 Gap Analysis](https://github.com/oidc-loki/oidc-loki/blob/main/tools/splice-check/docs/rfc8693-gap-analysis.md)). The root cause is in Section 2.1:

> "The authorization server MUST perform the appropriate validation procedures for the indicated token type."

This requires validation of each token's **type** — but never requires **cross-validation between** subject and actor. An AS that validates tokens independently is technically compliant. It's also vulnerable.

Other specification gaps compound the problem:

- **Section 1.1**: The `act` claim "can be used" (permissive) rather than "MUST be included" (normative). ASes can issue delegation-style tokens without `act` claims, making them indistinguishable from impersonation.
- **Section 4.1**: Nested `act` claims have no integrity requirements — no cycle detection, no depth limits, no restrictions on what claims can appear inside `act` objects.
- **Section 4.4**: The `may_act` authorization claim is described but enforcement is optional.
- **Section 5**: Client authentication is warned about but not required at a MUST level.

The security BCP ([RFC 9700](https://datatracker.ietf.org/doc/rfc9700/), January 2025) doesn't address delegation chain integrity either. There's a gap in the standards.

## Why This Matters Now: AI Agents

In traditional OAuth, delegation chains are short — usually one hop. A web app accesses an API on behalf of a user. The attack surface is limited.

AI agent architectures change this:

```
User → Orchestrator → Planner → Code Agent → GitHub API
                    → Scanner → Vuln DB API
                    → Deployer → Container Registry
                                → Kubernetes API
```

That's 3-4 hops with 5+ resource servers. Each hop is a token exchange. Each hop is a potential splice point. A compromised sub-agent can:

1. **Splice into parallel chains** — Access resources authorized for other agents
2. **Escalate scope** — Request broader permissions than its source token allows
3. **Persist access** — Retain delegation after the user revokes authorization
4. **Create circular chains** — Cause infinite loops or resource exhaustion

The attack surface scales with agent count and chain depth.

## Introducing splice-check

We built [splice-check](https://github.com/oidc-loki/oidc-loki/tree/main/tools/splice-check) to test Authorization Servers against these attacks. It sends 28 attack vectors across 7 categories:

| Category | Vectors | What It Tests |
|----------|---------|---------------|
| Core Splice | 5 | Cross-chain token combination, actor impersonation, audience bypass |
| Input Validation | 6 | Unauthenticated exchange, type escalation, scope abuse |
| Token Forgery | 2 | Fake issuer acceptance, expired token exchange |
| Edge Cases | 5 | Multi-audience, missing audience, may_act enforcement |
| Output Validation | 5 | Missing `act` claim, unconstrained audience, lifetime escalation |
| Chain Integrity | 2 | Circular delegation, depth exhaustion |
| Operational | 2 | Revocation propagation, refresh token bypass |

Each vector follows a three-phase pattern: **setup** (obtain legitimate tokens), **attack** (send malicious exchange request), **verify** (check if the AS caught it).

### Running It

```bash
cd tools/splice-check
npm install && npm run build

# Create config (three clients: user, legitimate agent, attacker agent)
npx splice-check --config my-as.toml

# CI/CD integration (exit code 1 = vulnerabilities detected)
npx splice-check --config my-as.toml --format json > results.json
```

### What Results Look Like

```
  splice-check v0.1.0
  Target: https://your-as.example.com/oauth2/token
  Tests:  28

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

- **PASS** — AS correctly handled the attack
- **FAIL** — AS is vulnerable
- **SKIP** — Inconclusive (infrastructure error, not a security judgment)

## The 8-Point Mitigation Profile

Based on the gap analysis, here's what AS implementers should do:

1. **Cross-validate subject and actor.** Verify the actor is authorized to act on behalf of the subject — via `aud` matching, `may_act` enforcement, or policy.

2. **Bind actor identity to client.** The authenticated client's identity must match `actor_token.sub`.

3. **Require client authentication.** The exchange endpoint must require authentication. No exceptions.

4. **Constrain output audience.** Every delegated token must have `aud` set to the intended downstream consumer.

5. **Preserve delegation semantics.** When `actor_token` is present, the result must include an `act` claim. Re-exchange must not strip it.

6. **Constrain token lifetime.** Delegated `exp` must not exceed the source token's `exp`.

7. **Enforce chain integrity.** Detect circular chains, limit depth (3-5 recommended), validate `act` nesting contains only identity claims.

8. **Propagate revocation.** Revoking a source token must invalidate all derived delegation tokens.

## Known CVEs

This isn't theoretical:

- **[CVE-2022-1245](https://nvd.nist.gov/vuln/detail/CVE-2022-1245)** — Keycloak privilege escalation via audience targeting in token exchange
- **CVE-2025-55241** — `act` claim stripping during re-exchange enables audit trail destruction

## What's Next

We've disclosed the delegation chain splicing vulnerability to the [IETF OAUTH-WG mailing list](http://www.mail-archive.com/oauth@ietf.org/msg25680.html). The gap analysis includes suggested normative language for each specification gap.

In the meantime, run splice-check against your AS. If you're building AI agent systems that use token exchange, the delegation attack surface is already there — the question is whether your AS validates it.

## Resources

- **Tool:** [splice-check on GitHub](https://github.com/oidc-loki/oidc-loki/tree/main/tools/splice-check)
- **Explainer:** [What Is Chain Splicing?](https://github.com/oidc-loki/oidc-loki/blob/main/tools/splice-check/docs/what-is-chain-splicing.md) (beginner)
- **Technical reference:** [28 Attack Vectors](https://github.com/oidc-loki/oidc-loki/blob/main/tools/splice-check/docs/attack-vectors.md)
- **Architecture patterns:** [Securing Delegation in Agentic Architectures](https://github.com/oidc-loki/oidc-loki/blob/main/tools/splice-check/docs/agentic-delegation-security.md)
- **Compliance:** [Security Posture Assessment Guide](https://github.com/oidc-loki/oidc-loki/blob/main/tools/splice-check/docs/security-posture-assessment.md)
- **Spec analysis:** [RFC 8693 Gap Analysis](https://github.com/oidc-loki/oidc-loki/blob/main/tools/splice-check/docs/rfc8693-gap-analysis.md)
- **For AI developers:** [AI Agent Delegation Guide](https://github.com/oidc-loki/oidc-loki/blob/main/tools/splice-check/docs/ai-agent-delegation-guide.md)

---

*splice-check is part of the [oidc-loki](https://github.com/oidc-loki/oidc-loki) project. For authorized security testing only.*
