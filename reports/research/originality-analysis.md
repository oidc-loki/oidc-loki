# Originality Analysis — What's Novel vs. Already Known

## Real-World Validation: CVE-2025-55241

Before discussing what's novel, a critical finding: **Microsoft's Entra ID actor token vulnerability (CVE-2025-55241, patched July 2025) directly validates several of our threat vectors.**

The vulnerability was exactly what we described in ACT-01/ACT-06/ACT-07:
- Actor tokens were **unsigned JWTs** that allowed cross-tenant impersonation
- No validation that the actor token originated from the correct tenant
- Bypassed MFA, Conditional Access, and **all logging** — zero audit trail
- Attacker could impersonate **any user including Global Admins** in **any tenant**
- Disclosed by researcher Dirk-jan Mollema

This is the real-world proof that `act` claim attacks are not theoretical — they're Critical severity in production.

**Source:** [dirkjanm.io — Obtaining Global Admin via Actor Tokens](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)

---

## Also Discovered: Agentic JWT (draft-goswami-agentic-jwt)

Neither of us initially found this — there's a **separate IETF draft** (December 2025) called "Agentic JWT" that defines:
- Per-agent proof-of-possession keys
- `agent_checksum` authorization grant (hash of prompt + tools + config)
- Chained delegation assertions
- Intent tokens binding agent actions to user intent

This should be added to our threat catalog as an 11th standard area.

**Source:** [IETF draft-goswami-agentic-jwt-00](https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/)

---

## Novelty Assessment

### Genuinely Novel (Not Found in Existing Literature)

| # | Threat | Who Found It | Why It's Novel |
|---|--------|-------------|----------------|
| 1 | **Chain Splicing** — combining steps from two different delegation chains into one apparently valid chain | Claude | Searched explicitly; no results. Kerberos ticket splicing is documented but OAuth `act` claim chain splicing is not. The attack exploits the fact that `act` claims are nested JSON objects — if individual steps aren't signed, steps from different chains can be recombined. |
| 2 | **Cryptographic DoS via mixed-algorithm delegation chains** — each link signed with PS512 or other expensive algo | Gemini | General crypto DoS exists, but the specific application to delegation chain verification where each nested `act` step forces a different expensive signature check is not documented. |
| 3 | **Auth code double-spend race condition in OBO agent flow** — two actors bound from one user consent | Gemini | Race conditions on auth codes are well-known, but this specific scenario (exploiting the `requested_actor` parameter to bind two different agents from one consent event) is novel to the OBO-for-AI-agents draft. |
| 4 | **Cross-standard attack chain: Prompt injection → RAR escalation → MCP exfiltration** | Gemini | Individual components are documented. The specific 3-stage chain combining ASI01 + RFC 9396 + MCP is not documented as a coherent attack path. |
| 5 | **Circular delegation via `act` claims** — A→B→A creating infinite validation loops | Claude | Circular delegation in Kerberos is well-studied. But OAuth `act` claim circular nesting is not — RFC 8693 doesn't address it and validators that recursively process `act` claims would loop infinitely. |

### Novel Due to Spec Recency (Specs Too New for Attack Research to Exist)

| # | Threat | Who Found It | Context |
|---|--------|-------------|---------|
| 6 | **OIDC-A `delegation_constraints` stripping/manipulation** | Claude | OIDC-A 1.0 is a September 2025 academic paper. No implementations exist yet, so any attack research is inherently first. |
| 7 | **Transaction token `agentic_ctx` manipulation** | Claude | draft-oauth-transaction-tokens-for-agents is at v03. Attacks on its `agentic_ctx` claim (modifying allowed actions mid-transaction) haven't been documented. |
| 8 | **OIDC-A attestation replay after agent compromise** | Claude | The attestation mechanism in OIDC-A is new. The specific attack of capturing valid attestation, compromising the agent, then replaying the old attestation is novel to this spec. |
| 9 | **Agent provider/type spoofing via OIDC-A claims** | Claude | Social engineering users by forging `agent_provider: "openai"` in OIDC-A consent flows. No prior research since the spec is new. |

### Insightful But Already Documented (in other forms)

| Threat | Status | Where It's Documented |
|--------|--------|----------------------|
| `act` claim injection/stripping | **Validated by CVE-2025-55241** | Microsoft Entra ID actor token research by Dirk-jan Mollema |
| MCP confused deputy via consent cookies | Documented | MCP spec security considerations, Descope, Composio |
| MCP tool poisoning | Documented | Docker blog, OWASP ASI02, multiple security vendors |
| DPoP downgrade/bypass | Documented | RFC 9449 security considerations |
| Prompt injection → token abuse | Documented | OWASP LLM01, multiple papers |
| Agent credential aggregation risk | Documented | OWASP ASI03, Aembit research |
| OAuth scope escalation | Documented | RFC 8693 §5, PortSwigger, Doyensec |
| Redirect URI bypass | Well-known | PortSwigger, HackTricks, extensive CVE history |
| SSRF via `jku`/`request_uri` | Well-known | CWE-918, OWASP SSRF |

### Enhanced Understanding (Known Concept, New Application)

| Threat | What's New About It |
|--------|-------------------|
| TOCTOU in token validation | Known pattern, but the specific risk in high-latency distributed agent systems (where revocation propagation is slow) is an under-appreciated application |
| Zombie agents | Agent lifecycle desynchronization is a new framing of stale credential problems specific to agent orchestration platforms |
| Recursive tool poisoning (Agent A → Agent B) | Cross-agent prompt injection propagation. Tool poisoning is documented but the transitive infection path through delegation chains is under-explored |
| DPoP key sharing across agent instances | DPoP assumes per-client keys, but agent deployments (hundreds of stateless instances) break this assumption in a way not covered by the RFC |

---

## Recommendation: What to Highlight

If publishing or presenting this research, these are worth calling out:

1. **Chain splicing** — genuinely novel, testable, and dangerous. Should be written up formally.
2. **CVE-2025-55241 as validation** — our theoretical `act` claim attacks were independently proven in the wild at Critical severity affecting every Microsoft tenant.
3. **Cross-standard attack chains** — the prompt injection → RAR → MCP chain is the kind of composed attack that individual spec authors wouldn't anticipate.
4. **Auth code double-spend in OBO** — novel race condition specific to the AI agent delegation flow.
5. **Agentic JWT (draft-goswami-agentic-jwt)** — a spec we both missed initially that introduces its own attack surface (`agent_checksum` manipulation, intent token forgery).

---

## Sources

- [CVE-2025-55241 — Entra ID Actor Token Vulnerability](https://dirkjanm.io/obtaining-global-admin-in-every-entra-id-tenant-with-actor-tokens/)
- [Agentic JWT IETF Draft](https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/)
- [Agentic JWT Paper](https://arxiv.org/html/2509.13597v1)
- [ConsentFix — OAuth Consent Hijacking](https://pushsecurity.com/blog/consentfix)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [Docker MCP Prompt Injection Horror Stories](https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/)
