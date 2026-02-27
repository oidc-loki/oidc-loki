# The Trust Gap in Agentic Delegation

*How the industry's zero-trust vision for AI agents outpaces the standards that are supposed to secure them*

---

Last week, Red Hat published a compelling piece on applying zero-trust principles to autonomous agentic AI systems. The core argument: as AI agents make access requests, fetch data, and orchestrate other agents, every hop in the chain needs explicit identity, scoped authorization, and auditability. No more implicit trust through forwarded tokens or shared API keys.

They're right. And they're not alone. The industry is converging on a model where each agent-to-agent delegation uses OAuth 2.0 Token Exchange (RFC 8693) to produce short-lived, scoped tokens with `act` claims that preserve the full delegation chain. WSO2 is building this into their Identity Server. Microsoft's Entra ID has been working through related challenges. The IETF OAuth working group has active drafts on identity chaining across domains and on-behalf-of flows for AI agents.

The vision is sound. But there's a gap between the vision and what the current specifications actually guarantee at the exchange boundary.

## The Model Everyone Is Building Toward

The architecture looks like this: a user authorizes an orchestrator agent, which delegates to downstream agents, each receiving a token scoped for its specific task. At every hop, the authorization server validates the delegation and issues a new token with an `act` claim recording who is acting on behalf of whom.

This is what RFC 8693 was designed for. Section 2.1 defines the `actor_token` parameter. Section 4.1 defines the `act` claim for recording delegation chains. Section 4.4 defines `may_act` for pre-authorizing specific actors.

Red Hat's article describes this model in detail -- delegated token exchange, audience scoping, short lifetimes, continuous verification. It's the right design.

## Where The Standards Fall Short

Here's the problem: RFC 8693 defines the *parameters* for delegation but not the *validation rules* that make delegation secure.

The specification tells an authorization server to accept a `subject_token` (representing the user's identity and authority) alongside an `actor_token` (representing the agent requesting to act). It describes how to encode the resulting delegation in an `act` claim. But it does not require the authorization server to verify that these two tokens belong to the same delegation context.

This means an authorization server that implements RFC 8693 as written can correctly process a token exchange request where the `subject_token` comes from one delegation chain and the `actor_token` comes from a completely different chain. The resulting token would carry an `act` claim that looks structurally valid but represents a delegation relationship that was never authorized.

What's missing is a binding between the two tokens. The spec does not require the authorization server to verify that the `subject_token` was issued *for* the actor presenting it -- for example, by checking that the token's intended audience matches the actor's identity. Without that check, the server validates each token independently but never confirms they belong to the same delegation flow. It's checking both tickets are genuine, but not that they're for the same journey.

The `may_act` claim (Section 4.4) helps -- it lets the subject pre-authorize specific actors. But `may_act` validates identity, not context. An agent that is legitimately authorized to act on behalf of a user in one workflow could present that authorization in a different workflow where it shouldn't apply.

I've raised this gap with the IETF OAuth working group and am actively working with the co-authors of draft-oauth-ai-agents-on-behalf-of-user on mitigations. The engagement has been productive. But the gap exists today, in a specification that the industry is building on for securing agentic AI.

## Why This Matters Now

This isn't a theoretical concern for three reasons.

**First, the attack surface is growing.** Every organization adopting agentic AI with multi-agent orchestration is building delegation chains. MCP (Model Context Protocol) interactions, A2A (agent-to-agent) workflows, and tool-use patterns all create the multi-hop trust relationships that depend on secure token exchange.

**Second, the prerequisites are low.** An attacker doesn't need to compromise the authorization server or steal signing keys. In multi-tenant agent platforms, tokens from different delegation chains are routinely available in the same environment -- passed through shared message buses, cached in common token stores, or delivered via cross-agent API calls as part of normal workflows. A malicious agent doesn't need to break in. It just needs to use a token it already has access to in a context it wasn't intended for.

**Third, the implementations are moving fast.** Keycloak added standard token exchange in version 26.2 (May 2025) and is working on MCP authorization support. WSO2 has delegation semantics in their Identity Server. Spring Authorization Server added token exchange in version 1.3. These are production deployments. The gap between "it works" and "it's secure against delegation-level attacks" needs to close before it's exploited.

## What's Being Done

The mitigations are well-understood. The authorization server needs to cross-validate that the `subject_token` was intended for the actor presenting it -- binding the token's audience to the actor's identity at each exchange. This needs to work alongside the `may_act` policy check, not replace it. Short token lifetimes and re-validation during token refresh limit exposure. Revocation needs to propagate through the delegation chain, not just terminate at the first hop.

These aren't exotic mechanisms. They're validation rules that an authorization server can enforce without changes to the token exchange protocol itself. RFC 8693 is a framework -- the framework is fine. What's needed is a security profile that specifies the validation behavior implementations MUST perform when tokens participate in delegation chains.

The IETF draft on AI agent authorization (draft-oauth-ai-agents-on-behalf-of-user) partially addresses this by binding the authorization code to the actor at the first hop. But delegation chains are typically deeper than one hop, and the binding needs to hold at every exchange, not just the initial one.

I'm working on a concrete mitigation profile and a conformance test methodology. More on that in a follow-up post.

## What You Should Do Now

If you're building agentic AI systems with delegation:

1. **Audit your token exchange implementation.** Does your authorization server cross-validate the `subject_token` and `actor_token`? Or does it accept any valid pair?

2. **Check your `aud` claim handling.** Are your delegated tokens issued with single-valued audience claims that identify the specific next actor in the chain? Multi-valued or missing audiences weaken the binding.

3. **Review your refresh flow.** When a delegated token is refreshed, does the authorization server re-validate the delegation context? Or does the refresh endpoint bypass the checks that the token exchange endpoint performs?

4. **Watch the IETF drafts.** The OAuth working group is actively addressing this. draft-oauth-ai-agents-on-behalf-of-user and draft-ietf-oauth-identity-chaining are both relevant.

The zero-trust model that Red Hat and others are advocating is the right architecture. The standards it depends on need to catch up.

---

*This is Part 1 of a series on securing delegation in agentic AI systems. Part 2 will detail the validation gaps and a proposed mitigation profile. Part 3 will provide a conformance test methodology for authorization server implementations.*

*Disclosure: AI-powered research tools were used to assist in the initial analysis. All findings have been independently validated by the author and disclosed to the IETF OAuth working group.*
