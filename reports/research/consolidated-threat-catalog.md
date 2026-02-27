# Consolidated Agentic OIDC Threat Catalog
## Claude + Gemini Collaborative Research — 2026-02-26

---

## Scope

This catalog covers **all** emerging OIDC/OAuth2 standards relevant to agentic use cases, synthesized from independent research by Claude and Gemini with adversarial cross-review.

**Standards Covered:** RFC 8693 (Token Exchange), draft-oauth-ai-agents-on-behalf-of-user (OBO for AI), OIDC-A 1.0, draft-oauth-transaction-tokens-for-agents, draft-goswami-agentic-jwt (Agentic JWT), RFC 9449 (DPoP), RFC 9396 (RAR), OIDC Federation, GNAP, RFC 9470 (Step-up Auth), MCP Authorization, OWASP Agentic Top 10 (2026)

**Real-World Validation:** CVE-2025-55241 (Microsoft Entra ID actor token vulnerability) independently proved our `act` claim injection/stripping threats at Critical severity — affected every Microsoft tenant.

---

## Priority Tier 0 — Critical (Must Implement First)

### P0-1: Token Exchange `act` Claim Attacks

**Standards:** RFC 8693 §4.1, draft-oauth-ai-agents-on-behalf-of-user

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| ACT-01 | No validation that `act.sub` matches authenticated client — actor impersonation | Critical | Claude |
| ACT-02 | Nested `act` claims treated as authoritative for access control (spec violation) | High | Claude |
| ACT-03 | `act` claims accepted from untrusted STS — forged delegation chains | Critical | Claude |
| ACT-04 | No max depth on nested `act` claims — parser confusion (downgraded from Critical by Gemini) | Medium | Both |
| ACT-05 | Non-identity claims inside `act` objects — validator confusion | Medium | Claude |
| ACT-06 | `act` claim stripping — converts delegation → impersonation | Critical | Claude |
| ACT-07 | Actor substitution — replace `act.sub` with different identity mid-chain | Critical | Claude |
| ACT-08 | Improper `act` construction — omitting delegation chain history | High | Gemini |

**Plugins:** `act-claim-injection`, `act-claim-stripping`, `act-depth-bomb` (configurable depth), `act-sub-substitution`, `act-non-identity-claims`

### P0-2: On-Behalf-Of User Authorization (OBO) Attacks

**Standards:** draft-oauth-ai-agents-on-behalf-of-user-02

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| OBO-01 | `requested_actor` not validated against `actor_token.sub` — actor impersonation | Critical | Claude |
| OBO-02 | Auth code not bound to (user, client, requested_actor) triple — actor swap | Critical | Claude |
| OBO-03 | PKCE not enforced for public clients — code interception | High | Claude |
| OBO-04 | Consent screen doesn't clearly identify agent — wrong delegation | High | Claude |
| OBO-05 | Missing `aut` claim — can't distinguish direct vs delegated access | High | Claude |
| OBO-06 | Auth code double-spend race condition — two actors from one consent | Critical | Gemini |
| OBO-07 | Social engineering via `requested_actor` hidden in authorization URL | Medium | Gemini |

**Plugins:** `requested-actor-mismatch`, `obo-pkce-bypass`, `obo-consent-actor-swap`, `obo-aut-claim-stripping`, `obo-code-double-spend`

### P0-3: Chained Delegation Attacks

**Standards:** RFC 8693, OIDC-A delegation_chain

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| CD-01 | No max chain depth policy — unbounded delegation | High | Both |
| CD-02 | Scope not reduced at each hop — privilege accumulation | Critical | Claude |
| CD-03 | No chronological ordering validation — forged chains | High | Claude |
| CD-04 | `aud` of step N != `sub` of step N+1 — broken chain | High | Claude |
| CD-05 | Individual chain steps not signed — intermediary forgery | Critical | Claude |
| CD-06 | Revocation of one link doesn't cascade — revoked agent persists | High | Claude |
| CD-07 | Circular delegation A→B→A — infinite loop | High | Claude |
| CD-08 | Chain-of-custody bypass — middle actor breaks chain | High | Gemini |
| CD-09 | Cryptographic DoS — each link uses expensive algo (PS512) | High | Gemini |
| CD-10 | Chain splicing — combining steps from different chains | High | Claude |

**Plugins:** `chain-extension`, `chain-splice`, `circular-delegation`, `chain-scope-widening`, `chain-chronology-violation`, `chain-link-revoked`, `crypto-exhaustion-chain`

### P0-4: Delegation vs Impersonation Confusion

**Standards:** RFC 8693 §1.1

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| DI-01 | Impersonation token issued when delegation requested — audit trail broken | Critical | Claude |
| DI-02 | No scope reduction on exchange — full privilege inheritance | Critical | Claude |
| DI-03 | Resource server can't tell delegation from impersonation — no `act` = impersonation | Critical | Both |

**Plugins:** `delegation-impersonation-confusion`, `scope-inheritance`

---

## Priority Tier 1 — High (Implement Second)

### P1-1: OIDC-A Agent Identity Attacks

**Standards:** OIDC-A 1.0 (arxiv 2509.25974)

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| OA-01 | `agent_type` spoofing — claim "assistant" when "autonomous" | High | Claude |
| OA-02 | `agent_provider` spoofing — claim to be "openai" when self-hosted | Critical | Claude |
| OA-03 | `agent_trust_level` self-assertion without attestation | Critical | Claude |
| OA-04 | `agent_instance_id` reuse — inherit another agent's reputation | High | Claude |
| OA-05 | `delegation_constraints` manipulation — remove operational restrictions | High | Claude |
| OA-06 | Attestation replay after agent compromise | High | Claude |
| OA-07 | Attestation stripping — remove entirely if not mandatory | High | Both |
| OA-08 | Friendly agent impersonation via social engineering of identity claims | High | Gemini |

**Plugins:** `agent-type-spoofing`, `agent-trust-escalation`, `delegation-constraint-stripping`, `attestation-replay`, `attestation-stripping`, `agent-provider-spoofing`

### P1-2: Transaction Tokens for Agents

**Standards:** draft-oauth-transaction-tokens-for-agents-03

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| TT-01 | Actor/principal values changed during token replacement — identity laundering | Critical | Claude |
| TT-02 | No `agentic_ctx` validation — agent exceeds authorized actions | High | Claude |
| TT-03 | Autonomous tokens without actor validation — unattributable actions | High | Claude |
| TT-04 | Missing principal in principal-initiated flows — no human accountability | High | Claude |
| TT-05 | Actor/principal injection during AT→TxnToken conversion | Critical | Claude |

**Plugins:** `txn-actor-injection`, `txn-principal-stripping`, `txn-context-manipulation`, `txn-replacement-forgery`

### P1-3: DPoP Agent Identity Binding

**Standards:** RFC 9449

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| DP-01 | Resource server doesn't check DPoP binding — stolen tokens usable | High | Claude |
| DP-02 | DPoP `ath` not validated — wrong token with same proof | High | Claude |
| DP-03 | No nonce/jti enforcement — proof replay | High | Both |
| DP-04 | `htu`/`htm` not validated — proof for GET reused for POST | High | Gemini |
| DP-05 | Missing `cnf` claim — token not actually bound to key | High | Gemini |
| DP-06 | DPoP downgrade — server accepts as bearer when proof missing | High | Both |
| DP-07 | Key sharing across agent instances — PoP for class not instance | Medium | Gemini |

**Plugins:** `dpop-proof-missing`, `dpop-ath-mismatch`, `dpop-nonce-replay`, `dpop-downgrade`, `dpop-htu-mismatch`, `dpop-cnf-missing`

### P1-4: MCP Trust Boundary Attacks

**Standards:** MCP Authorization Spec, OWASP ASI02/ASI04

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| MCP-01 | Tokens accepted without audience validation — cross-server reuse | High | Claude |
| MCP-02 | Tool descriptions not sandboxed — tool poisoning via metadata | Critical | Both |
| MCP-03 | No per-tool authorization scoping — over-permissioned access | High | Claude |
| MCP-04 | Confused deputy via consent cookie reuse | Critical | Claude |
| MCP-05 | No server identity verification — spoofing & rug-pull updates | High | Claude |
| MCP-06 | Cross-server shadowing — malicious server overrides trusted tools | Critical | Claude |
| MCP-07 | Recursive tool poisoning — Agent A poisons Agent B transitively | High | Gemini |

**Plugins:** `mcp-confused-deputy`, `mcp-tool-poisoning`, `mcp-cross-server-shadow`, `mcp-audience-bypass`

---

## Priority Tier 2 — Medium (Implement Third)

### P2-1: Rich Authorization Requests

**Standards:** RFC 9396

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| RAR-01 | `authorization_details` not validated against permitted actions | Critical (upgraded by Gemini review) | Both |
| RAR-02 | Type field not enumerated — arbitrary action types accepted | High | Claude |
| RAR-03 | No intersection with consented scope — privilege escalation | Critical (upgraded by Gemini review) | Both |
| RAR-04 | Complex object parsing errors → permissive interpretation | Medium | Gemini |

**Plugins:** `rar-type-injection`, `rar-detail-expansion`, `rar-scope-mismatch`, `rar-ignored`

### P2-2: OIDC Federation

**Standards:** OpenID Federation draft

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| FED-01 | Trust chain not validated to trust anchor | Critical | Both |
| FED-02 | Metadata policy not enforced | High | Claude |
| FED-03 | No freshness checking on metadata | Medium | Claude |
| FED-04 | Trust mark forgery | High | Claude |
| FED-05 | Agent joins malicious federation — credential exposure | High | Gemini |
| FED-06 | Metadata poisoning via MITM during discovery | High | Gemini |

**Plugins:** `federation-trust-chain-break`, `federation-metadata-policy-bypass`, `federation-trust-mark-forgery`, `federation-metadata-poisoning`

### P2-3: Step-up Authentication in Delegation Chains

**Standards:** RFC 9470

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| SU-01 | ACR inflation — high-trust `acr` without actual MFA | Critical | Gemini |
| SU-02 | ACR stripping from authorization request by MITM | High | Gemini |
| SU-03 | Step-up challenge reflection — tricking user into approving attacker's transaction | High | Gemini |
| SU-04 | Delegation chain confusion — who handles step-up challenge? | High | Gemini |
| SU-05 | Step-up loop — AS issues token without new `acr` after MFA | Medium | Gemini |
| SU-06 | `acr` not propagated down delegation chain — "step-down" | High | Gemini |

**Plugins:** `step-up-acr-spoof`, `step-up-loop-creator`, `bogus-acr-challenger`, `delegated-step-up-confusion`

### P2-4: GNAP

**Standards:** RFC 9635

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| GN-01 | Grant request injection — modify privileges in transit | High | Gemini |
| GN-02 | Continuation URI hijacking — inject fake response | High | Gemini |
| GN-03 | Ambiguous `access` array parsing — permissive interpretation | Medium | Gemini |

**Plugins:** `gnap-grant-modification`, `gnap-continuation-hijack`

### P2-5: Agentic JWT (draft-goswami-agentic-jwt)

**Standards:** draft-goswami-agentic-jwt-00 (December 2025 IETF draft)

Agentic JWT introduces an `agent_checksum` grant type where agent identity is a SHA-256 hash of (system prompt + tool specs + LLM config). Tokens include per-agent PoP keys via `cnf`, workflow step binding via `workflow_id`/`step_sequence_hash`, and `delegation_chain` hashes for multi-agent flows.

| ID | Threat | Severity | Source |
|----|--------|----------|--------|
| AJ-01 | `agent_checksum` collision — two different agent configs produce same hash via crafted prompts | High | Claude |
| AJ-02 | Checksum normalization mismatch — client and server normalize prompts differently, causing false rejections or false acceptances | High | Claude |
| AJ-03 | Shallow checksum bypass — tool logic changed but signature (name, description, params) unchanged | Critical | Claude |
| AJ-04 | `delegation_chain` hash truncation collision — only 16 hex chars used, increasing collision probability | Medium | Claude |
| AJ-05 | `step_sequence_hash` manipulation — skip workflow steps but forge the hash | High | Claude |
| AJ-06 | `registration_id` reuse after agent update — old tokens remain valid for modified agent | High | Claude |
| AJ-07 | Framework wrapper parameter stripping inconsistency — different frameworks strip different params, breaking checksum portability | Medium | Claude |
| AJ-08 | Intent token replay across workflow instances — valid token from workflow run A reused in run B | High | Claude |
| AJ-09 | `cnf` key extraction from agent process memory — PoP bypassed via key theft | High | Gemini (analogous to DPoP finding) |

**Attack Vectors:**
- **Shallow Checksum Bypass**: Attacker modifies a tool's internal logic (e.g., adds data exfiltration) but preserves its function signature. Shallow checksum (default) doesn't detect the change. Deep checksum via AST parsing is optional and computationally expensive.
- **Checksum Normalization Attack**: Exploiting whitespace/encoding differences between client-side and server-side SHA-256 computation. A prompt with Unicode homoglyphs or unusual line endings could hash differently on each side.
- **Workflow Step Skip**: Agent skips a required approval step but forges the `step_sequence_hash` by computing it over the expected step list rather than actual execution.
- **Delegation Chain Hash Collision**: The 16-hex-char truncated hash of pipe-delimited agent IDs creates a birthday-problem collision space of ~2^32. In large-scale agent deployments, different delegation paths could produce the same hash.

**Plugins:**
- `ajwt-shallow-checksum-bypass` — Modify tool logic while preserving function signature
- `ajwt-checksum-normalization` — Exploit prompt normalization differences
- `ajwt-workflow-step-skip` — Forge step_sequence_hash with skipped steps
- `ajwt-delegation-hash-collision` — Craft colliding delegation chain hashes
- `ajwt-intent-replay` — Replay intent tokens across workflow instances
- `ajwt-registration-reuse` — Use old registration_id after agent update

---

## Novel Findings (Original Research)

These threats were identified during this collaborative research and **could not be found in existing literature** as of February 2026.

### Validated by Real-World CVE

**CVE-2025-55241** (Microsoft Entra ID, patched July 2025) independently proves our `act` claim injection/stripping threats. Entra ID actor tokens were unsigned JWTs allowing cross-tenant impersonation of any user including Global Admins, bypassing MFA and all logging. Affected every Microsoft tenant.

*Source: [dirkjanm.io](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)*

### Genuinely Novel Threats

| ID | Threat | Discoverer | Novelty Basis |
|----|--------|-----------|---------------|
| NOVEL-01 | **Chain Splicing** — recombining steps from different `act` delegation chains into one valid-looking chain | Claude | No results found for OAuth-specific chain splicing. Exploits unsigned nested `act` JSON objects. |
| NOVEL-02 | **Crypto DoS via mixed-algorithm chains** — each nested delegation step signed with different expensive algo (PS512) | Gemini | General crypto DoS exists; specific application to delegation chain verification is new. |
| NOVEL-03 | **Auth code double-spend in OBO agent flow** — race condition binding two different agents from one user consent | Gemini | Novel to draft-oauth-ai-agents-on-behalf-of-user. |
| NOVEL-04 | **Prompt injection → RAR escalation → MCP exfiltration** — composed 3-stage cross-standard chain | Gemini | Individual components documented; the specific attack path is not. |
| NOVEL-05 | **Circular `act` claim delegation** — A→B→A causing infinite validator loops | Claude | Kerberos circular delegation is studied; OAuth `act` claim nesting is not. |
| NOVEL-06 | **Shallow checksum bypass in Agentic JWT** — tool logic changed but signature preserved | Claude | Spec is December 2025; no attack research exists. |
| NOVEL-07 | **OIDC-A delegation_constraints stripping** | Claude | Spec is September 2025 academic paper; no attack research exists. |
| NOVEL-08 | **Transaction token `agentic_ctx` manipulation** | Claude | draft-oauth-transaction-tokens-for-agents v03; no attack research exists. |
| NOVEL-09 | **Delegation chain hash truncation collision** in Agentic JWT | Claude | 16-hex-char truncation creates ~2^32 collision space. |

---

## Cross-Standard Combined Attacks (Novel — from adversarial review)

These represent the most sophisticated threats, combining vulnerabilities across multiple standards.

| ID | Attack Chain | Severity | Source |
|----|-------------|----------|--------|
| CS-01 | `jku` injection → forged JWKS → validates forged `act` claim → delegation hijack | Critical | Gemini |
| CS-02 | Prompt injection → RAR escalation → MCP data exfiltration | Critical | Gemini |
| CS-03 | TOCTOU: token validated → revoked → used (high-latency agent systems) | High | Gemini |
| CS-04 | Consent for Agent A → code intercepted → exchanged for Agent B (PKCE bypass) | Critical | Claude |
| CS-05 | Zombie agent (decommissioned but credentials live) → token exchange → active delegation | High | Gemini |
| CS-06 | Agent memory poisoning → persistent scope escalation across sessions | High | Claude |
| CS-07 | Redirect URI bypass in agent framework → token theft → impersonation | High | Gemini |
| CS-08 | SSRF via `request_uri` → internal cloud metadata → credential theft | High | Gemini |

---

## Implementation Infrastructure Threats (Identified by Gemini's Review)

| ID | Threat | Impact |
|----|--------|--------|
| INF-01 | Error message information leakage — reveals user existence, valid scopes, paths | Medium |
| INF-02 | Secret/key management failure — CI/CD leak, unencrypted keys | Critical |
| INF-03 | Agent lifecycle desynchronization — deleted agent retains valid credentials | High |
| INF-04 | Boilerplate configuration flaws — copy-pasted insecure defaults | High |
| INF-05 | Timing attack on chain validation — infer chain depth from response time | Medium |

---

## Complete Plugin Inventory

### Existing oidc-loki plugins (37) — Traditional OIDC attacks
*(Already implemented — signature, claims, flow, discovery, resilience)*

### New Agentic Plugins Proposed (~61)

**P0 — Must Have (18 plugins):**
1. `act-claim-injection` — Inject forged `act` claims
2. `act-claim-stripping` — Remove `act` (delegation→impersonation)
3. `act-sub-substitution` — Replace actor identity
4. `act-depth-bomb` — Configurable nested depth
5. `requested-actor-mismatch` — Consented vs exchanged actor differs
6. `obo-pkce-bypass` — Exchange without PKCE
7. `obo-consent-actor-swap` — Different actor at consent vs exchange
8. `obo-code-double-spend` — Race condition on auth code
9. `delegation-impersonation-confusion` — Wrong token semantics
10. `scope-inheritance` — No scope reduction on exchange
11. `chain-extension` — Append unauthorized delegation step
12. `chain-scope-widening` — Gradual privilege escalation
13. `circular-delegation` — A→B→A loop
14. `chain-splice` — Combine steps from different chains
15. `chain-link-revoked` — Include revoked agent
16. `token-type-indicator-mismatch` — Declared vs actual type
17. `subject-actor-swap` — Swap token roles
18. `unauthenticated-exchange` — Exchange without client auth

**P1 — Should Have (21 plugins):**
19. `agent-type-spoofing` — Misrepresent agent identity claims
20. `agent-provider-spoofing` — Claim trusted provider
21. `agent-trust-escalation` — Self-assert trust level
22. `delegation-constraint-stripping` — Remove operational restrictions
23. `attestation-replay` — Reuse old attestation
24. `attestation-stripping` — Remove attestation entirely
25. `txn-actor-injection` — Forge actor in transaction tokens
26. `txn-principal-stripping` — Remove human originator
27. `txn-context-manipulation` — Modify allowed actions
28. `dpop-proof-missing` — DPoP-bound token without proof
29. `dpop-ath-mismatch` — Wrong token hash
30. `dpop-nonce-replay` — Replay proofs
31. `dpop-downgrade` — Accept as bearer silently
32. `dpop-htu-mismatch` — Proof for wrong endpoint
33. `dpop-cnf-missing` — Token not bound to key
34. `mcp-confused-deputy` — Consent cookie reuse
35. `mcp-tool-poisoning` — Malicious tool metadata
36. `mcp-cross-server-shadow` — Override trusted tools
37. `mcp-audience-bypass` — Accept without audience check
38. `crypto-exhaustion-chain` — Expensive chain verification
39. `obo-aut-claim-stripping` — Remove authorization type

**P2 — Nice to Have (22 plugins):**
40. `rar-type-injection` — Unauthorized action types
41. `rar-detail-expansion` — Broaden permitted actions
42. `rar-scope-mismatch` — RAR vs scope inconsistency
43. `federation-trust-chain-break` — Break chain validation
44. `federation-metadata-policy-bypass` — Violate policy
45. `federation-trust-mark-forgery` — Fake trust marks
46. `federation-metadata-poisoning` — MITM metadata
47. `step-up-acr-spoof` — ACR without actual MFA
48. `step-up-loop-creator` — Missing `acr` in response
49. `bogus-acr-challenger` — Unsupported `acr` values
50. `delegated-step-up-confusion` — Wrong party handles challenge
51. `gnap-grant-modification` — Tamper with grant request
52. `gnap-continuation-hijack` — Inject fake response
53. `consent-gap-delegation` — No per-hop consent
54. `autonomous-agent-no-principal` — No traceable human
55. `act-non-identity-claims` — Spec-violating `act` content
56. `ajwt-shallow-checksum-bypass` — Modify tool logic, preserve signature
57. `ajwt-checksum-normalization` — Exploit prompt normalization diffs
58. `ajwt-workflow-step-skip` — Forge step_sequence_hash
59. `ajwt-delegation-hash-collision` — Craft colliding chain hashes
60. `ajwt-intent-replay` — Replay intent tokens across workflows
61. `ajwt-registration-reuse` — Old registration_id after update

---

## Architectural Considerations for oidc-loki

### New Mischief Phases Needed
The current 4 phases (token-signing, token-claims, response, discovery) need expansion:

| New Phase | Purpose |
|-----------|---------|
| `token-exchange` | Intercept and manipulate token exchange requests/responses |
| `delegation-chain` | Construct, modify, and inject delegation chains |
| `agent-identity` | Manipulate OIDC-A agent claims and attestation |
| `agent-checksum` | Manipulate Agentic JWT checksums, intents, and workflows |
| `consent-flow` | Manipulate the OBO consent/authorization flow |
| `dpop` | Manipulate DPoP proofs and bindings |

### New Capabilities Needed (from Gemini review)
1. **MITM Proxy Mode** — Intercept between client↔AS and client↔RS for flow-level attacks
2. **Race Condition Testing** — Concurrent request support for double-spend and TOCTOU tests
3. **Configurable Plugin Parameters** — All plugins should accept parameters (depth, scope list, timing, etc.)
4. **Multi-Service Simulation** — Simulate token exchange across multiple service boundaries

---

## References

### RFCs & Standards
- [RFC 8693 — Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [draft-oauth-ai-agents-on-behalf-of-user-02](https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/02/)
- [OIDC-A 1.0](https://arxiv.org/html/2509.25974v1)
- [Transaction Tokens for Agents](https://datatracker.ietf.org/doc/draft-oauth-transaction-tokens-for-agents/)
- [Agentic JWT — draft-goswami-agentic-jwt-00](https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/)
- [Agentic JWT Paper](https://arxiv.org/html/2509.13597v1)
- [RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449.html)
- [RFC 9396 — RAR](https://datatracker.ietf.org/doc/rfc9396/)
- [RFC 9470 — Step-up Auth](https://datatracker.ietf.org/doc/rfc9470/)
- [RFC 9635 — GNAP](https://datatracker.ietf.org/doc/rfc9635/)

### Real-World Vulnerabilities
- [CVE-2025-55241 — Entra ID Actor Token Impersonation](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)
- [CVE-2025-6514 — mcp-remote RCE](https://amlalabs.com/blog/oauth-cve-2025-6514/)

### Threat Frameworks
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OpenID Foundation — Identity Management for Agentic AI](https://openid.net/wp-content/uploads/2025/10/Identity-Management-for-Agentic-AI.pdf)

### Implementation Guidance
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [MCP Vulnerabilities (Descope)](https://www.descope.com/blog/post/mcp-vulnerabilities)
- [Strata — Agentic AI OAuth Guide](https://www.strata.io/blog/agentic-identity/why-agentic-ai-demands-more-from-oauth-6a/)
- [ISACA — Authorization Crisis](https://www.isaca.org/resources/news-and-trends/industry-news/2025/the-looming-authorization-crisis-why-traditional-iam-fails-agentic-ai)
