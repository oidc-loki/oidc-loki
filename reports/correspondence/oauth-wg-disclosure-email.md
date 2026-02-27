# Draft Email -- OAuth WG Disclosure

**To:** oauth@ietf.org
**Subject:** Security Consideration: Delegation Chain Splicing in RFC 8693 Token Exchange

---

Dear OAuth Working Group,

I am writing to share a security finding related to the `act` (actor) claim in RFC 8693 (OAuth 2.0 Token Exchange) that I believe warrants consideration, particularly as the working group advances specifications for agentic OAuth flows (draft-oauth-ai-agents-on-behalf-of-user, transaction tokens, etc.).

## Summary

I have identified a structural weakness I call **"delegation chain splicing"** -- a technique by which a compromised intermediary can present mismatched `subject_token` and `actor_token` inputs to the token exchange endpoint from different delegation contexts. The STS validates each token independently (per Section2.1-2.2), finds both valid, and issues a new properly-signed token asserting a delegation chain that never actually occurred.

The root cause is that RFC 8693 does not require cross-validation between the `subject_token` and `actor_token` -- specifically, there is no mechanism to verify they belong to the same delegation flow, authorization session, or trust context.

## Why This Matters Now

While RFC 8693 Section4.1 correctly states that nested `act` claims are "informational only" for access control, the proliferation of agentic AI systems creates deployment contexts where delegation chain history is increasingly relied upon for:

- Audit trail integrity (required under HIPAA, SOC 2)
- Policy enforcement ("was there a human in the loop?", "how many delegation hops?")
- Anomaly detection and trust scoring
- Compliance reporting

The `may_act` claim (Section4.4) provides partial mitigation by restricting which actors may exchange a token, but it validates the actor's *identity*, not that the actor credential was *acquired within the same delegation context*. It is also optional -- there is no normative requirement that subject tokens carry `may_act` or that the STS enforce it.

The draft-oauth-ai-agents-on-behalf-of-user specification takes a step in the right direction by binding the authorization code to the actor (Section5.5), but this protects only the initial user-to-agent delegation. Subsequent agent-to-agent token exchanges -- where chain splicing occurs -- remain unaddressed.

## Real-World Precedent

CVE-2025-55241 (Microsoft Entra ID, patched July 2025) demonstrated that actor token validation failures have Critical-severity impact in production. That vulnerability involved unsigned actor tokens enabling cross-tenant impersonation -- a closely related class of `act` claim misuse.

## Suggested Mitigations for Consideration

1. **Cross-validation requirement:** The STS should verify that the `actor_token` subject matches an authorized next-actor declared in the `subject_token` (strengthening `may_act` from optional to normative).

2. **`aud`/`sub` chaining within `act` claims:** Require that nested `act` claims include fields forming a verifiable chain -- similar to what OIDC-A 1.0 specifies for `delegation_chain`, where the `aud` of step N must match the `sub` of step N+1.

3. **Per-step delegation receipts:** Each STS that performs a token exchange includes a signed attestation of the delegation step, providing independently-verifiable provenance.

## Full Write-Up

A detailed write-up with three concrete scenarios (healthcare, multi-tenant SaaS, CI/CD), mechanism description, conditions for exploitability, anticipated counterarguments, and mitigations is attached.

This finding was independently validated by multiple analyses working from the RFC 8693 specification text alone.

I welcome feedback and am happy to discuss further.

Best regards,
[Your name]

---

*Note: This finding was identified during security research with the assistance of AI tools (Claude by Anthropic and Gemini by Google), which were used for collaborative analysis, adversarial review, and independent validation. I am sharing it with the working group for independent validation and consideration in ongoing specification work.*
