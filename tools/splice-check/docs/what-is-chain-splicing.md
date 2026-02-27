# What Is Delegation Chain Splicing?

> **Who this is for:** Developers, tech enthusiasts, and anyone who wants to understand a newly disclosed class of OAuth vulnerability without needing to read the RFCs.
>
> **Difficulty:** Beginner

## The One-Sentence Version

Delegation chain splicing is a technique where an attacker tricks an OAuth server into combining pieces from two separate trust chains into one, creating a forged delegation that never actually happened.

## First, What Is Token Delegation?

Imagine this scenario:

1. **Alice** logs into a web app and gets an access token
2. Alice's app needs **Agent A** (a microservice) to call another API on her behalf
3. The app asks the authorization server: "Here's Alice's token. Please give Agent A a new token that says Agent A is acting on behalf of Alice."

This is **delegation** — Alice didn't give Agent A her password. Instead, the authorization server issued a scoped, time-limited token that says "Agent A is acting for Alice." The resulting token contains a claim like:

```json
{
  "sub": "alice",
  "act": { "sub": "agent-a" }
}
```

The `act` (actor) claim is the key. It tells downstream services: "This token belongs to Alice, but Agent A is the one actually using it." This is the mechanism described in RFC 8693 (OAuth 2.0 Token Exchange).

## Now, What Goes Wrong?

The authorization server validates each token independently:

1. Is Alice's token valid? **Yes.**
2. Is Agent A's token valid? **Yes.**
3. OK, issue a new delegated token.

But what if step 1 and step 2 come from **different trust chains?**

## The Attack

Here's how an attacker (Agent N) exploits this:

```
Chain 1 (Legitimate):    Alice ──→ Agent A
Chain 2 (Attacker's):    Bob   ──→ Agent N

Agent N takes Alice's token from Chain 1
  and presents it with its own token from Chain 2:

  "Here's Alice's token (subject) and my token (actor).
   Please give me a delegated token."
```

The server checks:
- Alice's token? Valid.
- Agent N's token? Valid.
- Issue delegated token: "Agent N is acting for Alice."

**Agent N now has a token saying it acts for Alice — a delegation that Alice never authorized.**

This is the "splice" — two unrelated chains spliced together into a forged delegation.

```
                    ┌─────────────────┐
  Chain 1:   Alice ─┤                 │
                    │  Authorization  ├──→ "Agent N acts for Alice"
  Chain 2: Agent N ─┤    Server       │    (FORGED DELEGATION)
                    └─────────────────┘
```

## Why Does This Happen?

The root cause is that the authorization server validates each token in isolation. It checks:

- Is the subject token properly signed? Yes.
- Is the actor token properly signed? Yes.
- Are both tokens unexpired? Yes.

But it does **not** check:

- Did Alice actually authorize Agent N to act on her behalf?
- Does Alice's token say anything about Agent N being an allowed actor?
- Are these two tokens from the same trust context?

The specification (RFC 8693) describes the token exchange mechanism but does not mandate cross-validation between the subject and actor tokens.

## What Can Go Wrong in Practice?

| Scenario | Impact |
|----------|--------|
| Agent N splices into Alice's chain | Unauthorized access to Alice's resources |
| Agent N elevates to admin scope | Privilege escalation |
| Agent N targets internal services | Lateral movement inside the network |
| Circular delegation (A→N→A) | Infinite loops, DoS |
| Deep chains (A→B→C→D→E→...) | Token bloat, parser crashes |

## How Is It Detected?

The [splice-check](../README.md) tool sends 28 attack vectors against your authorization server to test whether it properly validates delegation chains. These include:

- **Basic splice** — Mix tokens from two different chains
- **Actor-client mismatch** — Present someone else's actor token
- **Audience binding** — Bypass audience restrictions
- **Circular delegation** — Create A→N→A loops
- **Chain depth exhaustion** — Stack 5+ delegation hops

Each test has three phases:
1. **Setup** — Obtain legitimate tokens
2. **Attack** — Send the malicious exchange request
3. **Verify** — Check if the server correctly rejected it

## How Is It Prevented?

Authorization servers should:

1. **Cross-validate subject and actor** — Verify the actor is authorized to act on behalf of the subject (e.g., check `aud` or `may_act` claims)
2. **Bind actor identity to client** — The authenticated client must match the actor token's identity
3. **Constrain output tokens** — Set tight `aud`, `exp`, and `scope` on delegated tokens
4. **Detect cycles** — Reject circular delegation chains
5. **Limit depth** — Enforce maximum chain depth

## Further Reading

- [splice-check README](../README.md) — Run the tool against your authorization server
- [Attack Vectors Reference](attack-vectors.md) — Technical details for all 28 tests
- [Securing Delegation in Agentic Architectures](agentic-delegation-security.md) — How AI agents make this worse
- [RFC 8693 Gap Analysis](rfc8693-gap-analysis.md) — Why the spec allows this attack

---

*splice-check is part of the [oidc-loki](https://github.com/oidc-loki/oidc-loki) project. For authorized security testing only.*
