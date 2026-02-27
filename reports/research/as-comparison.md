# Authorization Server Comparison: Keycloak vs WSO2 vs Rust (Build from Scratch)

**Date:** 2026-02-27
**Purpose:** Evaluate three approaches for implementing RFC 8693 delegation semantics with chain-splicing mitigations

---

## Side-by-Side Comparison

| Capability | Keycloak 26.5 | WSO2 IS 7.x | Rust (from scratch) |
|---|---|---|---|
| **RFC 8693 Token Exchange** | GA (V2 since 26.2) | Full support (built-in grant type) | Non-existent |
| **`actor_token` parameter** | Not implemented | Supported via OBO flow | Build from zero |
| **`act` claim emission** | Not implemented | Supported (nested chains) | Build from zero |
| **`may_act` claim** | Not implemented | Supported (ActAs rules) | Build from zero |
| **`aud`/`sub` cross-validation** | Not implemented | Standard validation; custom for cross-validation | Build from zero |
| **Delegation chains** | Not implemented | Supported (nested `act`) | Build from zero |
| **OIDC Provider** | Full, certified | Full, certified | No library exists |
| **Extension model** | Java SPI (TokenExchangeProvider) | Java OSGi (AuthorizationGrantHandler) | N/A -- you ARE the extension |
| **OBO draft alignment** | No (monitoring) | Active (co-author is WSO2 employee) | N/A |
| **MCP support** | Documented (26.5) | Not documented | N/A |
| **License** | Apache 2.0 | Apache 2.0 | N/A |
| **Admin UI** | Full React console | Full console + Asgardeo (cloud) | Build from scratch |
| **Community size** | Very large | Large (enterprise-focused) | Minimal for identity |

---

## Detailed Assessment

### 1. Keycloak

**What it has:** GA-quality RFC 8693 basic exchange (impersonation semantics), strong client policy enforcement, scope downscoping, token revocation chains, cross-domain identity chaining (preview), MCP authorization docs, massive community, Quarkus-based with fast startup.

**What it lacks:** Every delegation-specific feature -- `actor_token`, `act` claims, `may_act`, cross-validation. These are all listed as open issues (#12076 since 2022, #38279 since 2025). Red Hat's own blog post from yesterday acknowledges the gap.

**Extension difficulty:** Medium-High. The TokenExchangeProvider SPI is capable enough, but implementing full delegation requires understanding Keycloak's internal token model, session management, and protocol mapper pipeline. You're writing Java, packaging JARs, running `kc.sh build`.

**Risk:** Your custom SPI could break with Keycloak upgrades. If Keycloak adds native delegation support (likely, given Red Hat's stated interest), your custom code becomes technical debt that needs migration. You're building on someone else's foundation and hoping they don't rebuild that exact section.

**Time to working delegation:** 3-6 months of custom SPI development on top of a running Keycloak instance.

### 2. WSO2 Identity Server

**What it has:** Full RFC 8693 with `act` and `may_act` claims built in. ActAs validation rules. Nested delegation chains. The OBO draft co-author (Ayesha) works at WSO2, so the product tracks the draft closely. Extensible via custom grant handlers (Java/OSGi). Asgardeo cloud option for managed deployments.

**What it lacks:** Explicit `aud`/`sub` cross-validation requires custom handler. No documented chain-splicing prevention (this is the gap we identified). MCP authorization not documented. Steeper learning curve than Keycloak. OSGi architecture is less modern than Keycloak's Quarkus. Smaller community footprint.

**Extension difficulty:** Medium. The existing delegation infrastructure means you're adding validation logic on top of working delegation semantics, not building delegation from scratch. Custom `AuthorizationGrantHandler` for the cross-validation and chain-splicing mitigations.

**Risk:** WSO2's open-source vs enterprise feature boundary can be unclear. OSGi is aging as an architecture pattern. Smaller community means fewer people to help when you hit issues. However, the team actively building the OBO draft is at WSO2, which means the product will track the spec.

**Time to working delegation with mitigations:** 1-2 months. The delegation primitives exist; you're adding the security hardening we identified (aud/sub cross-validation, upstream splice prevention, refresh re-validation).

### 3. Rust (Build from Scratch)

**What Rust brings:** Memory safety without GC, sub-millisecond token operations, single static binary deployment (5-20MB containers), sub-second startup, no JVM overhead, excellent crypto libraries (ring, aws-lc-rs, rustls), strong JWT handling (jsonwebtoken at 12M+ downloads).

**What Rust lacks:** Everything above the HTTP and crypto layers. No OIDC Provider library (all Rust OIDC crates are client-only). No RFC 8693 implementation anywhere. oxide-auth is pre-1.0 with a single maintainer and no OIDC. Kanidm is a monolithic IdM, not a library, and has no RFC 8693. No CNCF presence for Rust identity projects.

**The real cost:** You're implementing OIDC discovery, JWKS, ID tokens, userinfo, token introspection, all OAuth 2.0 grant types, RFC 8693, `act`/`may_act`, delegation chain validation, admin APIs, admin UI, and conformance testing. Keycloak took years with a large team. Spring Authorization Server took years. You'd be doing it with fewer people.

**The real advantage:** Total control. No upgrade conflicts. No extension-point limitations. The architecture and security model are exactly what you design. Deployment is operationally simple. And your chain-splicing mitigations aren't bolted onto someone else's token model -- they're native.

**Time to working delegation with mitigations:** 6-12 months for a minimal but correct OIDC AS with RFC 8693 delegation. Longer for production hardening and OpenID Certification.

---

## The "Lift and Shift" Question

You asked whether building from scratch would be a "lift and shift" from Keycloak or WSO2. It wouldn't be, and here's why:

**Keycloak's architecture** is Quarkus + Hibernate/JPA + Infinispan + Java SPI. Its token model is deeply tied to its session management, realm model, and client representation. Porting this to Rust would mean rewriting the entire persistence and session layer. The useful knowledge you'd take from Keycloak is its *protocol implementation decisions* (how it structures token endpoints, what it validates, how it handles edge cases), not its code.

**WSO2's architecture** is OSGi + Carbon framework + Java. Same story -- the useful takeaway is the protocol behavior and the delegation semantics they've implemented, not the code.

**A Rust implementation** would use Axum for HTTP, jsonwebtoken for JWT, a purpose-built token model with `act`/`may_act` as first-class concepts, and your own policy engine. The internal architecture would look nothing like either Java platform. The only overlap would be adherence to the same RFCs, which is how standards are supposed to work.

---

## Decision Matrix

| Factor | Keycloak | WSO2 IS | Rust |
|---|---|---|---|
| Time to delegation | 3-6 months (custom SPI) | 1-2 months (extend existing) | 6-12 months |
| Chain-splicing prevention | Custom SPI | Custom handler on existing delegation | Native design |
| Upgrade risk | High (SPI contracts can change) | Medium (OSGi is stable but aging) | None (you own it) |
| Operational complexity | Medium-High (JVM + build phase) | Medium-High (JVM + OSGi) | Low (static binary) |
| Community/support | Largest | Large (enterprise) | Minimal |
| Conformance/certification | Certified (base), custom delegation untested | Certified (base), delegation features tested | Would need full certification |
| Contribution to spec work | Can demo mitigations on popular platform | Direct relationship with OBO draft authors | Original implementation, novel architecture |
| Long-term maintenance | Depend on Keycloak release cycle | Depend on WSO2 release cycle | Full ownership |
| UX/Configuration | Full admin console | Full console + Asgardeo cloud | Build your own |

---

## Recommendation

Three viable paths, each with a different value proposition:

**Path A: Extend WSO2 IS (Fastest to delegation mitigations)**
WSO2 already has the delegation primitives. You'd write custom grant handlers for aud/sub cross-validation, upstream splice prevention, and refresh re-validation. Ayesha is at WSO2 and already engaging on the OBO draft -- there's a natural collaboration path. Downside: OSGi architecture, steeper learning curve, smaller community.

**Path B: Extend Keycloak (Largest platform impact)**
Writing a Keycloak SPI that adds delegation semantics would benefit the largest community. Red Hat is publicly stating they need this. Downside: you're building the entire delegation layer from scratch inside someone else's extension model, and the 3-6 month timeline is aggressive.

**Path C: Build in Rust (Most original, highest control, longest timeline)**
A purpose-built AS where chain-splicing prevention is a first-class design constraint, not a bolt-on. Operationally superior deployment model. Original architecture that isn't a derivative of any existing platform. Downside: 6-12 months, no existing OIDC provider library, conformance testing burden.

**Hybrid option:** Build the reference implementation in Rust for the novel delegation/chain-splicing logic, and provide a Keycloak or WSO2 SPI/handler as a "bridge" for teams that need it on existing infrastructure. This lets you contribute to the spec discussion with both an original implementation and practical integration guidance.
