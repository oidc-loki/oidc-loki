# Agentic OIDC/OAuth2 Threat Catalog — Claude Research

## Executive Summary

This report catalogs misconfigurations, attack vectors, and novel threats across emerging OIDC/OAuth2 standards for agentic use cases. It covers 10 standard areas with 60+ distinct threat vectors, prioritizing AI-agent-specific risks that traditional OIDC testing tools (including oidc-loki's current 37 plugins) do not address.

---

## 1. Token Exchange (RFC 8693)

### 1.1 `act` Claim Attacks

**Severity: Critical**

The `act` claim identifies the acting party in a delegation. Nested `act` claims form delegation chains.

#### Misconfigurations
| ID | Misconfiguration | Impact |
|----|-----------------|--------|
| TE-01 | No validation that `act.sub` matches the authenticated client | Actor impersonation — any client can claim to act as any agent |
| TE-02 | Treating nested `act` claims as authoritative for access control | Spec violation (RFC 8693 §4.1): only top-level `act` should drive policy |
| TE-03 | Accepting `act` claims without verifying they were issued by a trusted STS | Forged delegation chains |
| TE-04 | No maximum depth enforcement on nested `act` claims | Token bloat DoS, parser confusion |
| TE-05 | Including non-identity claims (exp, nbf, aud) inside `act` objects | Spec violation that can cause validator confusion |

#### Attack Vectors
- **Actor Injection**: Attacker adds an `act` claim to a self-issued JWT to claim delegation authority they don't have
- **Actor Substitution**: Replace `act.sub` with a different agent's identity mid-chain
- **Nested Act Depth Bomb**: Deeply nested `act` claims (1000+ levels) causing stack overflow in recursive validators
- **Act Claim Stripping**: Remove the `act` claim entirely, converting a delegation token into an impersonation token
- **Ghost Actor**: Add `act` claim referencing a decommissioned/revoked agent identity that passes name-based checks but not liveness checks

#### Plugin Ideas for oidc-loki
- `act-claim-injection` — Inject forged `act` claims into tokens
- `act-claim-stripping` — Remove `act` to convert delegation→impersonation
- `act-depth-bomb` — Nest 100+ levels of `act` claims
- `act-sub-substitution` — Replace actor identity with attacker-controlled value
- `act-non-identity-claims` — Add exp/nbf/aud inside `act` (spec violation)

### 1.2 Subject Token / Actor Token Confusion

**Severity: Critical**

#### Misconfigurations
| ID | Misconfiguration | Impact |
|----|-----------------|--------|
| TE-06 | Accepting `subject_token` without `subject_token_type` | Type confusion — JWT vs SAML vs opaque |
| TE-07 | No validation that `actor_token` subject matches `requested_actor` | Actor impersonation at the token endpoint |
| TE-08 | Allowing unauthenticated clients to perform token exchange | Compromised token can be exchanged by anyone (RFC 8693 §5) |
| TE-09 | Not binding authorization code to `requested_actor` | Actor swap attack between consent and exchange |

#### Attack Vectors
- **Token Type Confusion**: Present an access token as `subject_token_type=urn:ietf:params:oauth:token-type:id_token` — validators may skip audience checks
- **Actor Token Replay**: Reuse a valid `actor_token` with a different user's `subject_token`
- **Subject-Actor Swap**: Swap subject_token and actor_token positions to invert the delegation relationship

#### Plugin Ideas
- `token-type-indicator-mismatch` — Mismatch between actual token type and declared type
- `subject-actor-swap` — Swap the two tokens' roles
- `unauthenticated-exchange` — Accept exchange requests without client auth

### 1.3 Delegation vs Impersonation Semantics

**Severity: High**

#### Misconfigurations
| ID | Misconfiguration | Impact |
|----|-----------------|--------|
| TE-10 | Not distinguishing delegation from impersonation in token format | Resource server can't tell if agent is acting "as" user or "on behalf of" |
| TE-11 | Issuing impersonation tokens when delegation was requested | Agent becomes indistinguishable from user — audit trail broken |
| TE-12 | No scope reduction when exchanging tokens | Delegated agent inherits full user privileges |

#### Attack Vectors
- **Delegation-to-Impersonation Escalation**: Request delegation but manipulate response to get impersonation token (no `act` claim = impersonation)
- **Scope Inheritance Attack**: Token exchange that preserves all original scopes instead of reducing to agent-appropriate subset

#### Plugin Ideas
- `delegation-impersonation-confusion` — Issue impersonation tokens when delegation requested
- `scope-inheritance` — Preserve full scope set during exchange (no reduction)

---

## 2. On-Behalf-Of User Authorization for AI Agents (draft-oauth-ai-agents-on-behalf-of-user)

**Severity: Critical — This is the emerging standard specifically for AI agent delegation**

### Misconfigurations
| ID | Misconfiguration | Impact |
|----|-----------------|--------|
| OBO-01 | `requested_actor` not validated against `actor_token.sub` at token endpoint | Actor impersonation — consent was for Agent A, token issued for Agent B |
| OBO-02 | Authorization code not bound to (user, client, requested_actor) triple | Actor swap between consent and exchange |
| OBO-03 | PKCE not enforced for public clients | Authorization code interception by malicious agents |
| OBO-04 | Consent screen does not clearly identify the agent | User unknowingly delegates to wrong agent |
| OBO-05 | Missing `aut` (authorization type) claim in access token | No way to distinguish direct vs delegated access |
| OBO-06 | Actor token accepted without signature verification | Forged agent identity |

### Attack Vectors
- **Consent Bait-and-Switch**: Show user consent for "Safe Agent" but swap `requested_actor` to "Malicious Agent" between consent and code exchange
- **Agent Identity Spoofing**: Present forged `actor_token` that claims to be a trusted agent
- **Scope Widening After Consent**: Request narrow scopes at consent time, then exchange with broader scope request
- **Missing PKCE Exploitation**: Intercept authorization code in agent-to-agent communication where redirect URIs are predictable

### Plugin Ideas
- `requested-actor-mismatch` — Mismatch between consented and exchanged actor
- `obo-pkce-bypass` — Perform exchange without PKCE validation
- `obo-consent-actor-swap` — Different actor at consent vs exchange time
- `obo-aut-claim-stripping` — Remove authorization type claim from access token

---

## 3. Chained Delegation

**Severity: Critical — Multi-hop delegation is the defining pattern of agentic systems**

### Misconfigurations
| ID | Misconfiguration | Impact |
|----|-----------------|--------|
| CD-01 | No maximum chain depth policy | Unbounded delegation chains — accountability lost |
| CD-02 | Scope not reduced at each delegation hop | Privilege accumulation through the chain |
| CD-03 | No chronological ordering validation of delegation steps | Forged historical chains |
| CD-04 | `aud` of step N not validated against `sub` of step N+1 | Broken chain — steps don't actually connect |
| CD-05 | Individual chain steps not signed | Any intermediary can forge or modify prior steps |
| CD-06 | Revocation of one link doesn't invalidate downstream | Revoked agent still has valid downstream tokens |

### Attack Vectors
- **Chain Extension Attack**: Append unauthorized delegation steps to an existing valid chain
- **Chain Splicing**: Take steps from two different chains and splice them together
- **Circular Delegation**: Agent A → Agent B → Agent A — creates infinite delegation loop
- **Ghost Link Injection**: Insert a delegation step for a decommissioned agent that still passes name checks
- **Scope Widening at Hop**: Each hop requests slightly broader scope than its predecessor, gradually escalating
- **Chain Replay**: Replay an entire delegation chain after the original purpose is complete

### Plugin Ideas
- `chain-extension` — Append unauthorized delegation step
- `chain-splice` — Combine steps from different delegation chains
- `circular-delegation` — Create A→B→A delegation loop
- `chain-scope-widening` — Gradually escalate scope through chain hops
- `chain-chronology-violation` — Delegation steps with out-of-order timestamps
- `chain-link-revoked` — Include a revoked agent in the chain

---

## 4. OIDC-A (OpenID Connect for Agents) Extension

**Severity: High — Emerging standard for LLM agent identity**

### New Claims Attack Surface
| Claim | Attack | Severity |
|-------|--------|----------|
| `agent_type` | Claim to be "assistant" when actually "autonomous" — bypass human-in-the-loop requirements | High |
| `agent_model` | Claim to be a trusted model (e.g., "gpt-4") when running a jailbroken variant | High |
| `agent_provider` | Spoof provider identity (claim to be "openai" when self-hosted) | Critical |
| `agent_instance_id` | Reuse another agent's instance ID to inherit its reputation/permissions | High |
| `agent_trust_level` | Self-assert "verified" trust level without attestation | Critical |
| `agent_capabilities` | Claim capabilities the agent doesn't actually have (or hide dangerous ones) | High |

### Delegation Chain Attacks (OIDC-A specific)
| ID | Attack | Impact |
|----|--------|--------|
| OA-01 | `delegation_chain` audience-subject chaining violation | Steps don't connect — forged chain |
| OA-02 | `delegation_constraints` manipulation | Remove operational restrictions on delegated agent |
| OA-03 | `delegation_purpose` spoofing | Legitimate-looking purpose hides actual intent |
| OA-04 | Scope in delegation step is superset of delegator's scope | Privilege escalation beyond delegator authority |

### Attestation Attacks
- **Attestation Replay**: Reuse a valid attestation from a previous session after the agent has been compromised
- **Attestation Forgery**: Generate fake attestation tokens without valid platform measurements
- **Nonce Reuse**: Replay attestation responses by reusing nonces
- **Attestation Stripping**: Remove `agent_attestation` entirely — relying parties that don't require it will accept

### Plugin Ideas
- `agent-type-spoofing` — Misrepresent agent type/model/provider
- `agent-trust-level-escalation` — Self-assert elevated trust without attestation
- `delegation-constraint-stripping` — Remove operational constraints from delegation
- `attestation-replay` — Replay old attestation after agent compromise
- `attestation-stripping` — Remove attestation entirely from token

---

## 5. Transaction Tokens for Agents (draft-oauth-transaction-tokens-for-agents)

**Severity: High**

### Misconfigurations
| ID | Misconfiguration | Impact |
|----|-----------------|--------|
| TT-01 | Actor and principal values changed during token replacement | Identity laundering through the call chain |
| TT-02 | No `agentic_ctx` validation against agent's actual capabilities | Agent exceeds authorized actions |
| TT-03 | Autonomous agent tokens issued without actor validation | Unattributable actions in the system |
| TT-04 | Missing principal in principal-initiated flows | No human accountability for agent actions |

### Attack Vectors
- **Actor/Principal Injection**: Forge actor or principal fields during access token → Txn-Token conversion
- **Context Manipulation**: Modify `agentic_ctx` to change allowed actions mid-transaction
- **Principal Stripping**: Remove principal from Txn-Token to hide human originator
- **Unauthorized Replacement**: Inject replacement Txn-Tokens at service boundaries

### Plugin Ideas
- `txn-actor-injection` — Forge actor identity in transaction tokens
- `txn-principal-stripping` — Remove principal to hide human originator
- `txn-context-manipulation` — Modify allowed actions mid-transaction
- `txn-replacement-forgery` — Forge replacement tokens at service hops

---

## 6. DPoP (RFC 9449) — Agent Identity Binding

**Severity: High**

### Misconfigurations
| ID | Misconfiguration | Impact |
|----|-----------------|--------|
| DP-01 | Resource server doesn't check DPoP binding on tokens | Stolen tokens usable without proof-of-possession |
| DP-02 | DPoP proof `ath` (access token hash) not validated | Different token can be used with same DPoP proof |
| DP-03 | No nonce enforcement for DPoP proofs | Replay attacks with captured proofs |
| DP-04 | DPoP key not rotated when agent is redeployed | Compromised key persists across deployments |

### AI-Agent Specific Threats
- **Key Sharing Between Agents**: Multiple agent instances sharing the same DPoP key — sender constraint is meaningless
- **DPoP Downgrade**: Agent requests token without DPoP, server issues bearer token instead
- **Proof Replay Window**: DPoP proofs with overly generous time windows allow replay

### Plugin Ideas
- `dpop-proof-missing` — Issue DPoP-bound token but don't require proof at resource
- `dpop-ath-mismatch` — DPoP proof doesn't match the token it accompanies
- `dpop-nonce-replay` — Accept replayed DPoP proofs
- `dpop-downgrade` — Downgrade from DPoP to bearer silently

---

## 7. Rich Authorization Requests (RFC 9396)

**Severity: Medium-High**

### Misconfigurations
| ID | Misconfiguration | Impact |
|----|-----------------|--------|
| RAR-01 | `authorization_details` not validated against agent's permitted actions | Agent authorized for actions beyond its scope |
| RAR-02 | Type field in authorization_details not enumerated/validated | Arbitrary action types accepted |
| RAR-03 | No intersection enforcement between RAR and consented scope | Agent gets more than user approved |

### Attack Vectors
- **Type Injection**: Add unexpected `type` values to `authorization_details` array
- **Detail Expansion**: Modify JSON objects within `authorization_details` to broaden permitted actions
- **RAR-Scope Mismatch**: Request narrow `scope` but broad `authorization_details`

### Plugin Ideas
- `rar-type-injection` — Inject unauthorized action types
- `rar-detail-expansion` — Broaden permitted actions in authorization details
- `rar-scope-mismatch` — Mismatched scope vs authorization_details

---

## 8. MCP (Model Context Protocol) Trust Boundary Attacks

**Severity: Critical — MCP is the primary integration surface for AI agents**

### Misconfigurations
| ID | Misconfiguration | Impact |
|----|-----------------|--------|
| MCP-01 | MCP server accepts OAuth tokens without audience validation | Cross-server token reuse |
| MCP-02 | Tool descriptions not validated/sandboxed | Tool poisoning via malicious metadata |
| MCP-03 | No per-tool authorization scoping | Over-permissioned tool access |
| MCP-04 | Static client IDs combined with dynamic client registration | Confused deputy via consent cookie reuse |
| MCP-05 | No server identity verification (TLS pinning, signed manifests) | Server spoofing and rug-pull updates |
| MCP-06 | Token storage in plaintext or environment variables | Credential theft at rest |

### Attack Vectors (from OWASP Agentic Top 10)
- **Tool Poisoning (ASI02)**: Malicious tool descriptions injected into LLM context influence all subsequent tool calls
- **Cross-Server Shadowing**: Malicious MCP server overrides tool definitions from trusted server
- **Confused Deputy**: MCP proxy server's consent cookies reused to authorize different clients
- **Rug-Pull**: Previously-safe MCP tool updated with malicious instructions (CVE-2025-6514)
- **NeighborJacking**: MCP server bound to 0.0.0.0 allows network-adjacent attackers full access

### Plugin Ideas
- `mcp-confused-deputy` — Exploit consent cookie reuse across clients
- `mcp-tool-poisoning` — Inject malicious metadata in tool descriptions
- `mcp-cross-server-shadow` — Override trusted tool definitions
- `mcp-audience-bypass` — Accept tokens without audience validation

---

## 9. OIDC Federation (Emerging)

**Severity: Medium-High**

### Misconfigurations
| ID | Misconfiguration | Impact |
|----|-----------------|--------|
| FED-01 | Trust chain not validated up to a trust anchor | Accept metadata from untrusted entities |
| FED-02 | Metadata policy not enforced at each federation level | Entity self-asserts capabilities beyond policy |
| FED-03 | No freshness checking on federation metadata | Stale/revoked entity metadata accepted |
| FED-04 | Trust mark signatures not validated | Forged trust assertions |

### Attack Vectors
- **Rogue Trust Anchor**: Attacker establishes themselves as a trust anchor in a poorly-validated federation
- **Metadata Policy Bypass**: Entity publishes metadata that violates federation policy constraints
- **Trust Mark Forgery**: Self-issue trust marks claiming compliance with standards

### Plugin Ideas
- `federation-trust-chain-break` — Break trust chain validation
- `federation-metadata-policy-bypass` — Violate federation policy constraints
- `federation-trust-mark-forgery` — Issue forged trust marks

---

## 10. AI-Agent Novel Threat Vectors (Cross-Cutting)

**Severity: Critical — These threats don't exist in traditional OIDC**

### 10.1 Prompt Injection → Token Abuse Chain
An attacker injects instructions via document/email/tool description that cause an AI agent to:
1. Request token exchange with escalated scope
2. Use the escalated token to access sensitive resources
3. Exfiltrate data through a side channel

**This is the most dangerous novel threat**: the agent's autonomous decision-making creates an entirely new attack surface where *the agent itself becomes the attack vector*.

### 10.2 Human Consent Gaps
- User consents to Agent A performing task X
- Agent A delegates to Agent B (sub-agent) without additional consent
- Agent B delegates to Agent C
- User has no visibility into or consent for Agent C's actions

### 10.3 Agent Memory Poisoning → Persistent Token Abuse
- Attacker poisons agent's long-term memory with instructions to always request maximum scopes
- Persists across sessions — agent "remembers" to escalate on every interaction

### 10.4 Identity Aggregation Risk (OWASP ASI03)
AI agents aggregate credentials from multiple systems:
- SSH keys cached in agent memory
- OAuth tokens from multiple resource servers
- API keys from MCP server configurations
- The agent becomes a single point of compromise for many identities

### 10.5 Autonomous Agent Accountability Gap
When no human principal initiated the action (scheduled/event-driven agents):
- Who is accountable for the agent's actions?
- How do you revoke access to an agent that has no human session?
- How do you audit decisions made by an agent acting autonomously?

### Plugin Ideas
- `consent-gap-delegation` — Agent delegates without propagating consent requirements
- `scope-escalation-on-exchange` — Agent requests maximum scopes during token exchange
- `autonomous-agent-no-principal` — Issue tokens with no traceable human principal
- `multi-hop-consent-bypass` — Multi-agent delegation with no per-hop consent

---

## Summary: Plugin Categories for oidc-loki Expansion

| Category | New Plugins | Priority |
|----------|-------------|----------|
| Token Exchange / `act` claim | 8 plugins | P0 — Critical |
| On-Behalf-Of Agent Auth | 4 plugins | P0 — Critical |
| Chained Delegation | 6 plugins | P0 — Critical |
| OIDC-A Agent Identity | 5 plugins | P1 — High |
| Transaction Tokens | 4 plugins | P1 — High |
| DPoP Agent Binding | 4 plugins | P1 — High |
| Rich Authorization Requests | 3 plugins | P2 — Medium |
| MCP Trust Boundaries | 4 plugins | P1 — High |
| OIDC Federation | 3 plugins | P2 — Medium |
| AI-Agent Novel Threats | 4 plugins | P0 — Critical |
| **Total** | **~45 new plugins** | |

---

## Sources

- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [draft-oauth-ai-agents-on-behalf-of-user-02](https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/02/)
- [OIDC-A 1.0 — OpenID Connect for Agents](https://arxiv.org/html/2509.25974v1)
- [Transaction Tokens for Agents](https://datatracker.ietf.org/doc/draft-oauth-transaction-tokens-for-agents/)
- [RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449.html)
- [RFC 9396 — Rich Authorization Requests](https://datatracker.ietf.org/doc/rfc9396/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OpenID Foundation — Identity Management for Agentic AI](https://openid.net/wp-content/uploads/2025/10/Identity-Management-for-Agentic-AI.pdf)
- [MCP Security Vulnerabilities](https://www.descope.com/blog/post/mcp-vulnerabilities)
- [Strata — Agentic AI Demands More from OAuth](https://www.strata.io/blog/agentic-identity/why-agentic-ai-demands-more-from-oauth-6a/)
- [ISACA — The Looming Authorization Crisis](https://www.isaca.org/resources/news-and-trends/industry-news/2025/the-looming-authorization-crisis-why-traditional-iam-fails-agentic-ai)
