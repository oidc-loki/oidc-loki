# Draft Reply to Ayesha

**Subject:** Re: Security Consideration: Delegation Chain Splicing in RFC 8693 Token Exchange

---

Dear Ayesha,

Thanks for the detailed response -- good to know this lines up with discussions you're already having. The mechanisms you're evaluating are exactly what I think is needed here.

Jumping into your questions:

### On the Intermediate Consent Step and "Verifiable Provenance"

Your precondition check is closer to my first mitigation (cross-validation at the exchange boundary) than to my third (per-step delegation receipts). Worth separating these:

- **Cross-validation** (what you're describing): The AS verifies at exchange time that the delegation is authorized -- "Is this sub-agent in a trusted tier? Does the user consent?" This stops the splice in real time.

- **Per-step delegation receipts** (my mitigation #3): Each exchange step produces a signed artifact that downstream parties can verify independently, without calling back to the AS. A chain of signed assertions: "AS-1 authorized Agent-X to delegate to Agent-Y at time T with scope S."

So your consent step prevents the splice; receipts prove after the fact that each step was authorized. They're complementary -- you could issue the receipt as part of the consent step.

I'd prioritize the consent step for the draft. Receipts matter in audit-heavy environments (healthcare, financial services) but add token size and complexity. They also help with an operational concern I'll get to below.

### On aud/sub Binding: Is It Strong Enough?

Short answer: yes, aud/sub binding is the right primitive. How well it holds up depends on enforcement and a few edge cases I've been thinking through.

The core mechanic works: If Alice's token carries `aud: "agent-X"`, and the STS requires `actor_token.sub` to match, then Agent-X can't present Agent-N's actor_token -- `sub: "agent-N"` doesn't match `aud: "agent-X"`. Splice blocked.

But there are edge cases worth working through:

1. **Upstream delegation splice.** This one concerns me the most. Agent-X legitimately holds Alice's token (aud: "agent-X"). Agent-X then requests a *new* token from the AS with aud: "agent-N" to enable sub-delegation. If the AS issues this without checking whether Agent-X is actually authorized to re-delegate to Agent-N on Alice's behalf, the splice just moves upstream -- Agent-X gets the AS to produce the mismatched token for it. Your precondition check is what closes this hole: the AS has to verify the re-delegation before issuing the new token. I'd suggest calling this out explicitly in the draft -- aud/sub binding prevents splicing at the exchange boundary, but without the precondition check, a malicious agent can effectively get the AS to splice on its behalf.

2. **Multi-instance actors.** In production, an "agent" is often a horizontally-scaled service behind a load balancer. Alice's token might have `aud: "agent-x-service"`, but the instance presenting the actor_token has `sub: "agent-x-instance-47"`. The simple equality check breaks. The AS would need to resolve service principal identifiers to sets of valid instance-level subjects. Not a blocker, but it's real implementation complexity.

3. **Multi-audience tokens.** A token with `aud: ["agent-X", "agent-Y", "agent-N"]` weakens the binding since multiple actors could satisfy the match. For delegation, I'd push for single-valued audience claims to keep the 1:1 binding strict.

4. **Missing audience claims.** `aud` is optional in JWTs. No `aud` on the subject_token means no binding, which means the splice is back on the table. Strong argument for making `aud` mandatory when tokens participate in delegation chains.

5. **STS-to-STS federation.** When delegation chains span multiple STSs across trust domains, each STS sets the audience for its own leg. A downstream STS trusts the upstream token's audience claim but can't verify the upstream STS actually performed the aud/sub check. A misconfigured upstream STS could issue tokens with overly permissive audience values.

6. **Revocation propagation.** If Alice revokes consent for Agent-X, the consent step prevents new delegations. But tokens already held by downstream agents (Agent-Y, Agent-Z) are still valid until they expire. You'd need to address chain-wide invalidation -- short lifetimes, back-channel revocation, or requiring resource servers to re-validate the full chain on each request.

7. **Token refresh as a bypass.** Related to revocation: if the AS issues refresh tokens alongside exchanged access tokens, the refresh flow (RFC 6749 Section 6) doesn't require re-presenting the subject_token or actor_token. An agent whose delegation has been revoked could still refresh its way to a new access token if the refresh endpoint doesn't re-validate the delegation context. DPoP (RFC 9449) dealt with a similar gap by requiring proof presentation on refresh, not just on initial requests. I'd suggest the draft include guidance along the lines of: "When refreshing tokens issued via delegated token exchange, the AS SHOULD re-validate the delegation context, including verifying that upstream consents remain active." Without that, the consent-per-step model has a quiet backdoor through the refresh endpoint.

### On may_act vs aud -- Simultaneous or Either/Or?

I think you need both, enforced together. They cover different failure modes:

- **aud/sub binding**: "Was this token *intended for* the actor presenting it?" -- a per-transaction binding that prevents misuse at the exchange boundary.

- **may_act**: "Is this actor *authorized* to act on behalf of this subject?" -- a policy declaration from the subject (or the AS on their behalf).

Each alone has gaps:
- aud/sub alone: Without the precondition check, a malicious agent can ask the AS to issue a token with aud matching any downstream actor (the upstream delegation splice from edge case #1).
- may_act alone: Validates identity but not that the actor_token came from the same delegation context -- the original gap.

Both together: the token has to be intended for the actor (aud) AND the subject has to have authorized that actor (may_act).

### On the Dynamic Discovery Problem

Agreed -- requiring the full chain upfront is impractical for real agent systems. The intermediate consent step handles this well: the AS verifies each delegation at exchange time while the chain gets built incrementally as agents discover what they need downstream.

There are some operational costs to this approach worth documenting in the draft:

- **Latency:** Every delegation hop in a chain of N agents adds a synchronous round-trip to the AS. For latency-sensitive orchestration this adds up.

- **Availability:** The AS becomes a single point of failure for every agent-to-agent delegation, not just user logins. An AS outage halts all agent collaboration. That's a meaningfully higher availability bar for AS infrastructure.

- **Offline/disconnected scenarios:** Consent-per-step is inherently online. For edge computing or intermittent connectivity, pre-signed delegation receipts (mitigation #3) are probably the better fit since they don't require an AS callback.

- **Backward compatibility:** On the upside, this should be backward-compatible at the protocol level. RFC 8693 is a framework; these are AS-side validation rules. Existing clients don't change -- the AS just gets stricter about what it permits.

Not reasons to avoid the approach, but trade-offs that implementers should understand.

### Pulling This Together

If I were writing a concrete mitigation profile, I'd combine your consent step with the binding mechanisms:

1. The AS MUST verify `subject_token.aud` matches `actor_token.sub` at each token exchange (with support for resolving service principal identifiers to instance-level subjects).
2. For delegation chains, the `subject_token` MUST carry a single-valued `aud` claim identifying the intended next actor.
3. The AS MUST validate the delegation against policy (may_act or equivalent) before issuing the new token.
4. The AS SHOULD issue the new token with `aud` set to the intended downstream actor, maintaining the binding through the chain.
5. Implementers SHOULD use short token lifetimes and consider back-channel revocation to limit exposure for downstream tokens after consent is withdrawn.
6. When refreshing tokens issued via delegated exchange, the AS SHOULD re-validate the delegation context, including verifying that upstream consents remain active.

Happy to keep this going and contribute to the draft if it's useful.

Best,
[Your name]
