# Keycloak Evaluation: RFC 8693 Token Exchange and Agentic Delegation

**Date:** 2026-02-27
**Current Keycloak Version:** 26.5.4 (released February 2026)
**Scope:** RFC 8693 compliance, delegation semantics, agentic AI readiness

---

## Table of Contents

1. [Token Exchange Support (RFC 8693)](#1-token-exchange-support-rfc-8693)
2. [act Claim Support](#2-act-claim-support)
3. [may_act Claim Support](#3-may_act-claim-support)
4. [aud/sub Validation at Exchange](#4-audsub-validation-at-exchange)
5. [Extension Points](#5-extension-points)
6. [Delegation Chain Depth](#6-delegation-chain-depth)
7. [Recent Activity](#7-recent-activity)
8. [Architecture](#8-architecture)
9. [Summary Assessment](#9-summary-assessment)

---

## 1. Token Exchange Support (RFC 8693)

### Current Status: Partially Implemented

Keycloak has **two co-existing token exchange implementations**:

#### Standard Token Exchange (V2) -- Fully Supported since Keycloak 26.2

Released in April 2025, this is the officially supported, GA-quality implementation. It is enabled by default and requires no feature flags.

**Supported parameters:**

| Parameter | Supported | Notes |
|---|---|---|
| `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` | Yes | Required |
| `subject_token` | Yes | The token being exchanged |
| `subject_token_type` | Yes | Must be `urn:ietf:params:oauth:token-type:access_token` or `urn:ietf:params:oauth:token-type:jwt` |
| `requested_token_type` | Yes | OAuth token types only (no SAML) |
| `audience` | Yes | Used for downscoping; defaults to requesting client |
| `scope` | Yes | Can be downscoped from original token |
| `actor_token` | **No** | Not implemented in V2 |
| `actor_token_type` | **No** | Not implemented in V2 |

**Scope of V2:** Internal-to-internal exchange only. A client exchanges its own Keycloak-issued access token for a new access token targeted at a different client within the same realm. This covers the "impersonation" semantics of RFC 8693 but **not** the "delegation" semantics.

**Token types supported in V2:**
- Input: `urn:ietf:params:oauth:token-type:access_token`, `urn:ietf:params:oauth:token-type:jwt`
- Output: OAuth 2.0 access tokens (JWT format). No SAML support.

#### Legacy Token Exchange (V1) -- Preview Feature

The older implementation remains available as a preview feature (not enabled by default; requires `--features=token-exchange` at startup). V1 supports four use cases:

1. Internal-to-internal token exchange (same as V2)
2. Internal-to-external exchange (e.g., exchange a Keycloak token for a linked Facebook token)
3. External-to-internal exchange (e.g., exchange an external IdP token for a Keycloak token)
4. Impersonation (a privileged client obtains a token on behalf of a different user)

V1 also does **not** support `actor_token` or delegation semantics. It allowed public clients to exchange tokens (V2 does not).

**Key difference:** You can enable V1 and V2 simultaneously and use them together. Red Hat recommends V2 for production use and V1 only for use cases V2 does not yet cover.

**Sources:**
- [Standard Token Exchange in Keycloak 26.2](https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2)
- [Keycloak Token Exchange Documentation](https://www.keycloak.org/securing-apps/token-exchange)
- [Token Exchange V2 features of V1 -- Issue #39686](https://github.com/keycloak/keycloak/issues/39686)
- [Red Hat Keycloak 26.4 Token Exchange Docs](https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/26.4/html/securing_applications_and_services_guide/token-exchange-)

---

## 2. act Claim Support

### Status: NOT IMPLEMENTED

Keycloak does **not** currently emit or validate the `act` (actor) claim defined in RFC 8693 Section 4.1. Since delegation semantics are not implemented (no `actor_token` parameter support), there is no mechanism to produce tokens with nested `act` claims.

**What would be needed:**
- Accept `actor_token` and `actor_token_type` parameters on the token exchange endpoint
- Validate the actor token
- Emit an `act` claim in the resulting JWT containing at minimum a `sub` claim identifying the actor
- For chained delegation, nest `act` claims within `act` claims

**Workaround possibilities:**
- A custom protocol mapper could theoretically inject an `act` claim into tokens, but without native actor_token processing, the mapper would lack the actor identity context needed to populate the claim correctly.
- A custom `TokenExchangeProvider` SPI implementation could intercept the exchange request, parse an `actor_token` from the request parameters, and construct the `act` claim manually.

**Relevant GitHub issues:**
- [Support for delegation in token exchange (Issue #12076)](https://github.com/keycloak/keycloak/issues/12076) -- opened 2022, still open
- [Support for token-exchange delegation (Issue #38279)](https://github.com/keycloak/keycloak/issues/38279) -- opened 2025, still open
- [Token exchange delegation discussion (#43108)](https://github.com/keycloak/keycloak/discussions/43108) -- opened October 2025

---

## 3. may_act Claim Support

### Status: NOT IMPLEMENTED

Keycloak does **not** support the `may_act` claim defined in RFC 8693 Section 4.4. This claim, when present in a subject token, asserts which parties are authorized to act on behalf of the token's subject.

**What RFC 8693 Section 4.4 specifies:**
- The `may_act` claim is a JSON object within a JWT that identifies parties eligible to act for the subject
- It contains claims like `sub`, `iss`, and others that identify the authorized actor
- The authorization server SHOULD cross-validate that the `actor_token`'s subject matches what the `may_act` claim authorizes

**Gap impact:** Without `may_act` support, there is no way to pre-authorize specific actors for delegation within a token. Any delegation authorization must be handled externally or via custom SPI logic.

**Sources:**
- [RFC 8693 Section 4.4](https://www.rfc-editor.org/rfc/rfc8693.html#section-4.4)
- [Issue #12076 discussion](https://github.com/keycloak/keycloak/issues/12076)

---

## 4. aud/sub Validation at Exchange

### Current Behavior: Independent Validation (No Cross-Validation)

Since Keycloak does not accept `actor_token`, there is no cross-validation between `subject_token.aud` and `actor_token.sub`. However, Keycloak does perform meaningful validation on the `subject_token` and the requesting client:

**What Keycloak validates today:**

1. **subject_token.aud must include the requesting client:** The subject_token sent to the token exchange endpoint must have the requester client set as an audience in the `aud` claim. If the client is exchanging its own token (where it was the original audience), this is automatically satisfied. Otherwise, the request is rejected.

2. **Audience downscoping:** The `audience` parameter filters which audiences appear in the resulting token. If omitted, it defaults to the requesting client.

3. **Scope enforcement:** The `downscope-assertion-grant-enforcer` client policy executor ensures requested scopes do not exceed those in the original subject_token. Only downscoping is permitted.

4. **Client policy conditions:** Administrators can create client policies with combined conditions for `client-scope`, `grant-type`, and `client-roles` to restrict which clients can perform exchanges and under what conditions.

**What Keycloak does NOT validate:**
- No `actor_token.sub` vs `subject_token.may_act` cross-validation (neither parameter exists)
- No verification that a specific actor is authorized to act for a specific subject
- No delegation chain integrity checks

**Implication for agentic flows:** Without cross-validation, any client with the right permissions can exchange any valid subject_token. The trust model relies on client authentication and client policies rather than token-level delegation authorization.

**Sources:**
- [Keycloak Token Exchange Documentation](https://www.keycloak.org/securing-apps/token-exchange)
- [Red Hat Keycloak 26.2 Token Exchange Docs](https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/26.2/html/securing_applications_and_services_guide/token-exchange-)

---

## 5. Extension Points

### SPI Architecture: Highly Extensible

Keycloak's extension model is built on Java Service Provider Interfaces (SPIs). The relevant extension points for token exchange are:

#### TokenExchangeProvider SPI

The primary extension point for custom token exchange logic. Defined at:
`org.keycloak.protocol.oidc.TokenExchangeProvider`

**Interface design:**
- `supports()` -- determines if this provider can handle a given token exchange request
- `exchange()` -- performs the actual token exchange logic
- `close()` -- cleanup

The `TokenExchangeProviderFactory` includes `getPriority()` for deterministic ordering when multiple providers are registered.

**What you can do with it:**
- Handle exchange to/from non-OAuth clients and non-OAuth IdPs
- Recognize and validate tokens issued by third-party entities
- Implement custom delegation logic including `act` claim generation
- Add custom validation of `actor_token` parameters from the raw HTTP request

**Design document:** [token-exchange-spi.md](https://github.com/keycloak/keycloak-community/blob/main/design/token-exchange-spi.md)

**Example implementations:** [Token Exchange SPI Examples](https://github.com/dteleguin/token-exchange-spi-examples)

#### Protocol Mapper SPI

Custom protocol mappers can add claims to tokens, including exchanged tokens. This could be used to inject `act` claims, though the mapper would need to retrieve actor context from somewhere (e.g., session notes, request parameters).

**Key consideration:** Protocol mappers are applied to all tokens from a client, not just exchanged ones. There are ongoing discussions ([Issue #30358](https://github.com/keycloak/keycloak/issues/30358)) about applying mappers differently based on the token exchange pattern.

#### Client Policy Executors

Custom client policy executors can enforce arbitrary rules during token exchange. The built-in `downscope-assertion-grant-enforcer` is one example. Custom executors could:
- Restrict which clients can exchange with which audiences
- Enforce scope limitations
- Reject exchanges based on custom business logic

#### Deployment Model

1. Implement `ProviderFactory` interface
2. Register via `META-INF/services/<FullyQualifiedFactoryInterface>` (standard Java ServiceLoader)
3. Package as a JAR file
4. Drop the JAR into Keycloak's `/providers` directory
5. Run `kc.sh build` to re-augment (if using optimized mode)
6. Configure via `--spi-{spi-name}-{provider-id}-{property}={value}`

#### Difficulty Assessment

| Task | Difficulty | Notes |
|---|---|---|
| Custom protocol mapper (add static claims) | Low | Well-documented, many examples |
| Custom client policy executor | Medium | Less documentation, but straightforward SPI |
| Custom TokenExchangeProvider | Medium-High | Must understand internal token model, session management |
| Full delegation with act claims | High | Requires TokenExchangeProvider + custom validation logic + act claim construction |

**Sources:**
- [Keycloak Server Developer Guide](https://www.keycloak.org/docs/latest/server_development/)
- [TokenExchangeProvider Javadoc](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/protocol/oidc/TokenExchangeProvider.html)
- [Token Exchange SPI Design](https://github.com/keycloak/keycloak-community/blob/main/design/token-exchange-spi.md)
- [Keycloak Provider Configuration](https://www.keycloak.org/server/configuration-provider)

---

## 6. Delegation Chain Depth

### Status: No Native Support, No Limits Defined

Since Keycloak does not natively produce `act` claims, there are no built-in limits on delegation chain depth. However:

**Token revocation chains do exist:** When a token obtained via exchange is itself used for further exchange, revoking the original token revokes the entire chain of exchanged tokens. This is a session-level mechanism, not a claim-level one.

**If implementing via custom SPI:**
- There are no Keycloak-imposed limits on JSON nesting depth in JWTs
- Practical limits would come from JWT size (typically capped at ~8KB for HTTP headers)
- Each delegation hop adds approximately 50-200 bytes of nested `act` JSON
- A reasonable practical limit would be around 10-20 delegation levels before JWT size becomes problematic

**RFC 8693 itself does not specify a limit** on delegation chain depth. It describes the nesting pattern but leaves depth limits to implementations.

**Security considerations:** The IETF OAuth working group has raised concerns about [delegation chain splicing attacks](http://www.mail-archive.com/oauth@ietf.org/msg25680.html), where an attacker combines act claims from different delegation chains to construct unauthorized delegation paths. Any custom implementation should validate chain integrity.

---

## 7. Recent Activity

### Active Development and Growing Ecosystem Interest

#### Keycloak 26.5 (January 2026): JWT Authorization Grant + Identity Chaining

The most significant recent development is the JWT Authorization Grant feature (RFC 7523 support), which enables cross-domain identity chaining when combined with RFC 8693 token exchange:

- **RFC 7523 grant type:** A client presents a signed JWT assertion to obtain an access token without interactive authorization
- **Identity chaining:** The IETF draft "OAuth Identity and Authorization Chaining Across Domains" combines RFC 7523 with RFC 8693 to preserve user identity across domain boundaries
- **Status:** Keycloak 26.5 can be considered to support the latest draft of the "Authorization Chaining across domains" specification, as it supports both token-exchange (for "domain-a") and RFC 7523 grant (for "domain-b", currently a preview feature)

This is relevant to agentic delegation because it enables a pattern where an agent in Domain A can obtain scoped tokens to access resources in Domain B while preserving the original user's identity.

**Source:** [JWT Authorization Grant and Identity Chaining in Keycloak 26.5](https://www.keycloak.org/2026/01/jwt-authorization-grant)

#### MCP Authorization Support (Issue #41521)

Keycloak is actively working on Model Context Protocol authorization support:

- Keycloak now provides OAuth 2.0 Server Metadata via RFC 8414 well-known URI
- Documentation added for using Keycloak as MCP authorization server
- **Gap:** The latest MCP specification (2025-06-18) requires support for resource indicators, which Keycloak does not yet implement
- A dedicated guide exists: [Integrating with MCP](https://www.keycloak.org/securing-apps/mcp-authz-server)

#### Red Hat Blog: Zero Trust for Agentic AI (February 26, 2026)

Red Hat published a significant blog post just yesterday describing their vision for securing agentic AI systems:

- Proposes delegated token exchange for each hop in an agent chain
- Each call should use a scoped, short-lived token issued specifically for that hop
- Explicitly calls out the limitation that Keycloak currently supports impersonation but not delegation
- Advocates for RFC 8693 delegation semantics with `act` claims for auditability

**Source:** [Zero Trust for autonomous agentic AI systems](https://next.redhat.com/2026/02/26/zero-trust-for-autonomous-agentic-ai-systems-building-more-secure-foundations/)

#### Open Issues and Discussions

| Issue | Title | Status | Opened |
|---|---|---|---|
| [#12076](https://github.com/keycloak/keycloak/issues/12076) | Support for delegation in token exchange per RFC 8693 | Open | 2022 |
| [#38279](https://github.com/keycloak/keycloak/issues/38279) | Support for token-exchange delegation | Open | 2025 |
| [#43108](https://github.com/keycloak/keycloak/discussions/43108) | Token exchange delegation (discussion) | Open | Oct 2025 |
| [#41521](https://github.com/keycloak/keycloak/issues/41521) | MCP Authorization specification support | In Progress | 2025 |
| [#30358](https://github.com/keycloak/keycloak/issues/30358) | Add claims to exchanged token in Token Exchange | Open | 2024 |
| [#26502](https://github.com/keycloak/keycloak/discussions/26502) | Token-Exchange Use-cases | Open | 2023 |
| [#45466](https://github.com/keycloak/keycloak/issues/45466) | Documentation for Authorization Chaining Across Domains | Open | 2026 |

#### Community Talks and Presentations

- [KeyConf25: Token Exchange -- Keycloak's Secret Weapon for Platforms](https://keyconf.dev/2025/assets/files/sven-torben-janus-token-exchange.pdf) (Sven-Torben Janus)
- [Keycloak Dev Day 2025: Token Exchange](https://keycloak-day.dev/assets/files/20250306_KeycloakDevDay_TokenExchange.pdf)
- [Keycloak Dev Day 2026: AI, MCP and Security](https://www.innoq.com/en/talks/2026/03/ai-mcp-and-security-keycloak-devday-2026/) (upcoming, March 2026)
- [MCP Authorization for Agentic AI -- The Confused Deputy](https://medium.com/@sauravkumarsct/mcp-authorization-for-agentic-ai-the-confused-deputy-5af8bb835261) (Sourav Kumar, Jan 2026)

---

## 8. Architecture

### Tech Stack

| Component | Technology |
|---|---|
| **Language** | Java (requires Java 17+) |
| **Runtime** | Quarkus (superseded WildFly/JBoss in Keycloak 17+) |
| **Build** | Maven (50+ modules in hierarchical POM structure) |
| **Database** | PostgreSQL (recommended), MySQL, MariaDB, Oracle, MSSQL, H2 (dev only) |
| **Persistence** | Hibernate/JPA |
| **Clustering** | Infinispan (embedded) |
| **HTTP** | Vert.x (via Quarkus) |
| **Admin UI** | React (PatternFly) |
| **Container Image** | `quay.io/keycloak/keycloak` |

### Deployment Model

- **Container-native:** The Quarkus-based distribution is optimized for container deployments (Docker/Kubernetes)
- **Two-phase build:** An augmentation/build phase pre-processes configuration and optimizes the runtime, followed by the actual startup
- **Fast startup:** Quarkus provides sub-second startup times in optimized mode
- **Kubernetes Operator:** An official Keycloak Operator is available for Kubernetes/OpenShift deployments
- **Configuration:** Environment variables, CLI flags, or `keycloak.conf` file

### Key Architecture Points for Extension Development

- SPIs are discovered via Java `ServiceLoader` at startup
- Custom providers are JARs dropped into `/opt/keycloak/providers/`
- After adding providers, `kc.sh build` must be run to re-augment
- Provider configuration follows `--spi-{name}-{provider}-{property}` pattern
- The Quarkus build phase means hot-deployment of providers is not possible; a restart with rebuild is required

**Sources:**
- [Keycloak Server Developer Guide](https://www.keycloak.org/docs/latest/server_development/)
- [Migrating to Quarkus Distribution](https://www.keycloak.org/migration/migrating-to-quarkus)
- [Keycloak Quarkus Architecture (DeepWiki)](https://deepwiki.com/keycloak/keycloak/4.1-quarkus-integration)

---

## 9. Summary Assessment

### Scorecard

| Capability | Status | Rating |
|---|---|---|
| RFC 8693 basic token exchange | GA (V2, since 26.2) | Supported |
| Internal-to-internal exchange | GA | Supported |
| External-to-internal exchange | Preview (V1 only) | Partial |
| Internal-to-external exchange | Preview (V1 only) | Partial |
| `actor_token` / `actor_token_type` parameters | Not implemented | Gap |
| `act` claim emission | Not implemented | Gap |
| `act` claim validation | Not implemented | Gap |
| `may_act` claim | Not implemented | Gap |
| `aud`/`sub` cross-validation (actor vs subject) | Not implemented | Gap |
| Delegation chain support | Not implemented | Gap |
| Client policy enforcement on exchange | GA | Supported |
| Scope downscoping on exchange | GA | Supported |
| Custom TokenExchangeProvider SPI | Available | Supported |
| Custom protocol mappers | Available | Supported |
| JWT Authorization Grant (RFC 7523) | Preview (26.5) | Partial |
| Cross-domain identity chaining | Preview (26.5) | Partial |
| MCP authorization server | Documented (26.5) | Partial |

### Key Gaps for Agentic Delegation

1. **No `actor_token` support** -- The fundamental building block for delegation is missing from the standard token exchange. This is the single largest gap.

2. **No `act` claim** -- Without actor token processing, there is no way to produce tokens that transparently represent "A acting on behalf of B."

3. **No `may_act` claim** -- No mechanism to pre-authorize specific actors within a token, meaning all delegation authorization must be handled at the policy level.

4. **No cross-validation** -- The authorization server cannot verify that a given actor is authorized by the subject's token to act on their behalf.

### What Keycloak CAN Do Today for Agentic Flows

- **Scoped token exchange:** An agent orchestrator can exchange a user's token for a more narrowly scoped token (fewer audiences, fewer scopes) before passing it to a downstream agent. This is the pattern Red Hat advocates in their Zero Trust blog post.
- **Client policy enforcement:** Restrict which clients can perform exchanges and with what parameters.
- **Token revocation chains:** Revoking an original token cascades to all exchanged tokens in the chain.
- **Cross-domain identity chaining (preview):** Combine RFC 8693 + RFC 7523 to chain identity across realms/domains.
- **Custom SPI for delegation:** A custom `TokenExchangeProvider` could implement the full delegation flow including `act` claim generation, but this requires significant development effort.

### Recommendation

For a project requiring RFC 8693 delegation semantics (act claims, may_act validation, delegation chains), Keycloak requires **custom SPI development** to fill the gaps. The extension model is capable enough to support this, but it represents a Medium-High difficulty effort. The Keycloak community is actively discussing delegation support, and Red Hat's interest in agentic AI security suggests these features may arrive natively in a future release (likely post-26.5). Monitor issues [#38279](https://github.com/keycloak/keycloak/issues/38279) and [#12076](https://github.com/keycloak/keycloak/issues/12076) for progress.

---

## Appendix: Key References

- [Keycloak Token Exchange Documentation](https://www.keycloak.org/securing-apps/token-exchange)
- [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
- [Keycloak Server Developer Guide](https://www.keycloak.org/docs/latest/server_development/)
- [Token Exchange SPI Design Document](https://github.com/keycloak/keycloak-community/blob/main/design/token-exchange-spi.md)
- [JWT Authorization Grant in Keycloak 26.5](https://www.keycloak.org/2026/01/jwt-authorization-grant)
- [MCP Integration Guide](https://www.keycloak.org/securing-apps/mcp-authz-server)
- [Zero Trust for Agentic AI (Red Hat)](https://next.redhat.com/2026/02/26/zero-trust-for-autonomous-agentic-ai-systems-building-more-secure-foundations/)
- [MCP Authorization for Agentic AI -- The Confused Deputy](https://medium.com/@sauravkumarsct/mcp-authorization-for-agentic-ai-the-confused-deputy-5af8bb835261)
- [KeyConf25 Token Exchange Presentation](https://keyconf.dev/2025/assets/files/sven-torben-janus-token-exchange.pdf)
