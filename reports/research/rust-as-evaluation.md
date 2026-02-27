# Rust Ecosystem Evaluation: OAuth 2.0 / OIDC Authorization Server with RFC 8693 Token Exchange

**Date**: 2026-02-27
**Purpose**: Evaluate the feasibility and maturity of the Rust ecosystem for building a production-grade OAuth 2.0 / OIDC Authorization Server, with specific focus on RFC 8693 Token Exchange (including `act`/`may_act` claims).

---

## Table of Contents

1. [Existing AS Implementations in Rust](#1-existing-as-implementations-in-rust)
2. [Key Libraries](#2-key-libraries)
3. [RFC 8693 Support](#3-rfc-8693-support)
4. [Web Frameworks](#4-web-frameworks)
5. [Configuration UX](#5-configuration-ux)
6. [Deployment](#6-deployment)
7. [Comparison to Java/TypeScript](#7-comparison-to-javatypescript)
8. [Notable Projects](#8-notable-projects)
9. [Honest Assessment and Recommendation](#9-honest-assessment-and-recommendation)

---

## 1. Existing AS Implementations in Rust

### Kanidm -- The Only Serious Contender

[Kanidm](https://github.com/kanidm/kanidm) is the most notable Rust-based identity management platform. It is a complete identity management system (not just an AS library) that includes OAuth2/OIDC provider functionality alongside LDAP, RADIUS, SSH key distribution, and Unix/Linux integration.

| Attribute | Details |
|-----------|---------|
| Language | Rust |
| GitHub Stars | ~2.6k |
| License | MPL-2.0 |
| Maturity | Active development, production use in some environments |
| OIDC Support | Yes -- OAuth2/OIDC provider with PKCE S256, ES256 token signing, RFC 9068 JWT access tokens |
| Target | Small-to-medium identity management (home labs to enterprise) |

**Key limitations for our use case**: Kanidm is a *complete identity platform*, not a composable library. It is opinionated about its identity store (built-in database), authentication flows, and cryptographic choices. You cannot easily extract its OAuth2/OIDC engine and use it independently. It does **not** implement RFC 8693 Token Exchange, `act` claims, or `may_act` claims.

### oxide-auth -- The Library Approach

[oxide-auth](https://github.com/HeroicKatora/oxide-auth) is the most established OAuth2 *server library* for Rust.

| Attribute | Details |
|-----------|---------|
| Version | 0.6.1 (pre-1.0) |
| Downloads | ~1.3M all-time on crates.io |
| Last update | Over 1 year ago (as of early 2026) |
| Maintainer | Single maintainer with limited time |
| Framework support | Actix, Rocket, Iron, Rouille, Axum (via oxide-auth-axum) |
| API stability | Unstable -- explicitly pre-1.0 |

**What it provides**: Authorization Code, Implicit, Client Credentials, and Resource Owner Password grants. Configurable and pluggable backends for token storage. Framework-agnostic core with adaptor crates.

**What it lacks**: No OIDC layer (no ID tokens, no discovery, no userinfo). No RFC 8693 Token Exchange. No `act`/`may_act`. No JWT-based access tokens out of the box. Single maintainer with sporadic activity.

### auth-framework

[auth-framework](https://github.com/ciresnave/auth-framework) claims to be a comprehensive authentication and authorization framework with OAuth2 server and OIDC provider capabilities.

| Attribute | Details |
|-----------|---------|
| Downloads | ~3,800 all-time |
| Versions | 7 |
| Maturity | Very low adoption |

**Honest assessment**: Despite marketing language ("military-grade security," "battle-tested"), the download numbers tell the real story. With fewer than 4,000 total downloads, this has minimal community validation. The claims of "production-ready" and "used by multiple companies" are not verifiable from public data. Not a serious option for production use.

### Summary: No production-grade Rust AS exists as a composable library

The honest reality is that there is **no production-grade, general-purpose OAuth 2.0 / OIDC Authorization Server library in Rust** comparable to:
- **Java**: Spring Authorization Server, Keycloak (as a platform), or the libraries behind Authlete
- **TypeScript/Node**: node-oidc-provider, oidc-provider
- **Go**: Ory Hydra/Fosite, Dex, ZITADEL
- **.NET**: Duende IdentityServer, OpenIddict

Kanidm is a product, not a library. oxide-auth is a library but covers only OAuth2 (not OIDC), is pre-1.0, and has a single maintainer. Everything else has negligible adoption.

---

## 2. Key Libraries

### JWT Creation/Validation

| Crate | Downloads | Version | Algorithms | Notes |
|-------|-----------|---------|------------|-------|
| [jsonwebtoken](https://github.com/Keats/jsonwebtoken) | 12M+ | 10.3.0 | HS256/384/512, RS256/384/512, PS256/384/512, ES256/384, EdDSA | **Best option.** Mature, well-maintained, strongly typed. |
| [josekit](https://docs.rs/josekit) | Moderate | Current | Full JOSE stack (JWT, JWS, JWE, JWA, JWK) | Based on OpenSSL. More comprehensive but adds OpenSSL dependency. |
| [jwt-simple](https://crates.io/crates/jwt-simple) | Moderate | Current | Multiple | Higher-level, more opinionated. Automatic signature verification. |
| [biscuit](https://github.com/lawliet89/biscuit) | Lower | Older | Multiple | JOSE library. Less actively maintained. |

**Recommendation**: `jsonwebtoken` is the clear winner for JWT operations. For full JOSE stack (JWE, JWK management), `josekit` fills gaps. Neither provides `act`/`may_act` claim handling out of the box -- you would implement those as custom claims.

### OIDC Provider Functionality

| Crate | Purpose | Provider Support? |
|-------|---------|-------------------|
| [openidconnect](https://github.com/ramosbugs/openidconnect-rs) | OIDC **client** (Relying Party) | **No** -- client only |
| [openid](https://crates.io/crates/openid) | OIDC **client** | **No** -- client only |
| [axum-oidc](https://lib.rs/crates/axum-oidc) | OIDC middleware for Axum | **No** -- RP middleware only |

**Critical gap**: There is **no dedicated OIDC Provider library** for Rust. All the OIDC crates are Relying Party (client) libraries. To build an OIDC Provider, you would need to implement:
- Discovery document (`/.well-known/openid-configuration`)
- JWKS endpoint
- ID Token generation with standard claims
- UserInfo endpoint
- Token introspection
- All from scratch, using `jsonwebtoken` for the JWT layer

### OAuth 2.0 Server Framework

Only `oxide-auth` exists as a server-side OAuth2 library (covered above). The `oauth2` crate by ramosbugs is a **client** library, despite sometimes being mistakenly referenced as server-side.

### Cryptographic Operations

| Crate | Purpose | Status |
|-------|---------|--------|
| [ring](https://docs.rs/ring) | Cryptographic primitives | 334M+ downloads. Mature. Slightly limited algorithm set. |
| [aws-lc-rs](https://crates.io/crates/aws-lc-rs) | Cryptographic primitives (AWS fork of ring API) | Now the **recommended** default for rustls. Better performance, post-quantum support. |
| [rustls](https://github.com/rustls/rustls) | TLS implementation | Production-grade. Memory-safe TLS. No OpenSSL dependency. |
| [ed25519-dalek](https://crates.io/crates/ed25519-dalek) | EdDSA signatures | Mature, from the RustCrypto project. |
| [p256](https://crates.io/crates/p256) / [p384](https://crates.io/crates/p384) | ECDSA | RustCrypto ecosystem. |

**Assessment**: The cryptographic foundation in Rust is **excellent**. This is one area where Rust genuinely excels -- `ring`, `aws-lc-rs`, and `rustls` are production-grade and widely deployed. The crypto layer is not a concern.

---

## 3. RFC 8693 Support

### Direct answer: Zero Rust implementations exist

No Rust library implements RFC 8693 Token Exchange. Specifically:

- **No `urn:ietf:params:oauth:grant-type:token-exchange` grant type** is implemented in any Rust OAuth2 library.
- **No `act` claim handling** exists in any Rust JWT library (you would add it as a custom serde-serializable claim).
- **No `may_act` claim processing** exists anywhere in the Rust ecosystem.
- **No `subject_token` / `actor_token` parameter handling** exists.
- **No delegation vs. impersonation semantics** are implemented.

### What building it yourself would look like

If you were to implement RFC 8693 in Rust, you would need:

1. **Token endpoint extension**: A new grant type handler for `urn:ietf:params:oauth:grant-type:token-exchange`
2. **Custom claims in JWT**: Define `act` and `may_act` as serde structs, serialize/deserialize with `jsonwebtoken`
3. **Policy engine**: Authorization logic for deciding when token exchange is permitted, delegation chain validation, chain-splicing prevention
4. **Token type handling**: `urn:ietf:params:oauth:token-type:access_token`, `urn:ietf:params:oauth:token-type:id_token`, `urn:ietf:params:oauth:token-type:jwt`

This is a substantial implementation effort. For comparison:
- **Keycloak** only reached *standard* RFC 8693 compliance in version 26.2 (May 2025), after years of a non-standard preview implementation.
- **Spring Authorization Server** added token exchange support in version 1.3 (March 2024).
- Both of these projects have large teams and years of OAuth/OIDC engineering behind them.

### Comparison to other ecosystems

| Language/Platform | RFC 8693 Support | Maturity |
|-------------------|-----------------|----------|
| Java (Keycloak) | Standard support since 26.2 (2025) | High (but took years of iteration) |
| Java (Spring Auth Server) | Since 1.3 (2024) | Medium-High |
| .NET (Duende IdentityServer) | Via RSK extension | High |
| TypeScript (node-oidc-provider) | Configurable grant types | Medium |
| Go (Ory Hydra/Fosite) | Custom grant extensibility | Medium |
| **Rust** | **Nothing** | **Non-existent** |

---

## 4. Web Frameworks

### Axum -- The Recommended Choice

[Axum](https://github.com/tokio-rs/axum) is the clear recommendation for building an AS in Rust today.

| Attribute | Axum | Actix Web |
|-----------|------|-----------|
| Backing | Tokio team | Community |
| Middleware | Tower ecosystem | Actor model |
| Performance | Excellent (slightly lower raw throughput) | Highest throughput (10-15% advantage under extreme load) |
| Memory usage | Lower | Slightly higher |
| Adoption | Most popular Rust web framework (2023+ surveys) | Second most popular |
| DX | Simpler, standard Rust patterns | More complex, custom abstractions |
| OAuth2 integration | oxide-auth-axum exists | oxide-auth-actix exists |

**Why Axum wins for an AS**:
- Tower middleware is composable and well-suited for the layered processing an AS needs (authentication, rate limiting, audit logging, CORS, etc.)
- Deep Tokio integration matters for an AS that needs to handle concurrent token operations, key rotation, and async backend calls
- The larger ecosystem of Axum extractors and middleware makes building HTTP-level OAuth2 semantics more natural
- More active development and larger contributor base

### Production readiness for AS use case

Both Axum and Actix Web are **production-ready** web frameworks. The question is not "can they handle HTTP?" but rather "what AS-specific functionality do they provide?" The answer is: very little beyond basic HTTP handling. You are building the AS logic on top of them.

---

## 5. Configuration UX

### Configuration Management

The Rust ecosystem has solid configuration management options:

| Crate | Features | Maturity |
|-------|----------|----------|
| [config](https://crates.io/crates/config) | TOML, JSON, YAML, INI, env vars; layered; hierarchical | **Standard choice.** Widely used. 12-factor app support. |
| [figment](https://crates.io/crates/figment) | Multi-source, strongly typed, env-aware | Good alternative, used by Rocket |
| [envy](https://crates.io/crates/envy) | Deserialize env vars into structs | Lightweight, env-only |
| [dotenvy](https://crates.io/crates/dotenvy) | .env file loading | Standard for dev environments |

The `config` crate supports the layered approach ideal for an AS: defaults in code, overridden by config files (TOML/YAML), overridden by environment variables. This is comparable to what you get in Spring Boot or Node.js.

### Admin APIs

There is no Rust equivalent of Keycloak's Admin REST API or Spring Authorization Server's management endpoints. You would build these from scratch using Axum routes.

### Admin Web UIs

Rust has emerging frontend frameworks:
- **Leptos** (~18.5k GitHub stars): Full-stack, fine-grained reactivity, SSR support. Most promising.
- **Dioxus**: React-like, cross-platform (web, desktop, mobile).
- **Yew**: Component-based, inspired by React/Elm.

However, building an admin UI in Rust WASM is a significant additional effort compared to using a React/Vue/SPA front-end that talks to Axum REST APIs. For an AS admin UI, using a TypeScript SPA (React, Vue, or even htmx) with a Rust API backend is more pragmatic.

**Honest assessment**: The configuration *file* story is good. The admin API and UI story requires building everything from scratch. Compare this to Keycloak's full admin console, Spring's management endpoints, or node-oidc-provider's configuration object.

---

## 6. Deployment

### The Rust Deployment Advantage

This is where Rust genuinely shines:

**Static Binary Distribution**:
- Compile to a single static binary (with musl target: `x86_64-unknown-linux-musl`)
- No runtime dependencies (no JVM, no Node.js, no Python interpreter)
- Binary size: typically 5-20MB for a web service
- Cross-compilation is well-supported

**Docker**:
- Multi-stage builds: compile in a Rust builder image, copy binary to `scratch` or `distroless`
- Final images can be under 10MB (compared to 200-500MB for Java/Node)
- `FROM scratch` is viable -- the binary is the entire container
- Reduced attack surface: no shell, no package manager, no OS utilities in the final image

**Example Dockerfile pattern**:
```dockerfile
FROM rust:1.82 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/my-as /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/my-as"]
```

**Resource consumption**:
- Memory: Rust AS would typically use 10-50MB RSS vs 200-500MB for a JVM-based AS or 50-150MB for a Node.js AS
- CPU: No GC pauses, predictable latency
- Startup: Sub-second vs 5-30 seconds for Spring/Keycloak

**Operational story**:
- Systemd service files work well for bare-metal/VM deployment
- Kubernetes/container orchestration is straightforward due to small image sizes
- No runtime version management (no "which JDK?" or "which Node version?")
- Observability: `tracing` crate ecosystem provides structured logging, OpenTelemetry integration

---

## 7. Comparison to Java/TypeScript

### Genuine Advantages of Rust for an AS

| Advantage | Details | Impact |
|-----------|---------|--------|
| **Memory safety without GC** | No null pointer exceptions, no use-after-free, no data races -- at compile time | High for security-critical AS code |
| **Performance** | 10-100x lower memory usage, sub-millisecond token operations, no GC pauses | Moderate -- most AS are not bottlenecked on compute |
| **Binary distribution** | Single binary, no runtime dependencies | High for operational simplicity |
| **Container size** | 5-20MB images vs 200-500MB | Moderate -- reduces attack surface |
| **Startup time** | Sub-second cold start | High for serverless/edge deployments |
| **Dependency security** | cargo-audit, compile-time checks, smaller dependency trees | Moderate |

### Genuine Disadvantages of Rust for an AS

| Disadvantage | Details | Impact |
|--------------|---------|--------|
| **No OIDC provider library** | Must build OIDC layer from scratch | **Critical** -- massive additional effort |
| **No RFC 8693 implementation** | Must implement token exchange from zero | **Critical** -- the core feature we need |
| **Development speed** | 2-4x slower initial development vs TypeScript/Java | High |
| **Ecosystem maturity** | OAuth/OIDC server ecosystem is years behind Java/Go/TS | **Critical** |
| **Community size** | Far fewer identity/auth engineers using Rust | High -- harder to find contributors, security reviewers |
| **Conformance testing** | No OpenID Certification path established for Rust | High -- credibility and correctness |
| **Learning curve** | Ownership, lifetimes, async complexity | Moderate -- team capacity factor |
| **Security audit cost** | Custom-built AS needs thorough audit; no existing audited implementations | High |
| **Iteration speed** | Compile times, borrow checker friction during rapid prototyping | Moderate |

### Head-to-head for this specific use case

| Criterion | Rust | TypeScript (node-oidc-provider) | Java (Spring Auth Server / Keycloak) |
|-----------|------|------|------|
| RFC 8693 support | Build from scratch | Extensible grants (some work) | Built-in (Keycloak 26.2, Spring 1.3) |
| OIDC Provider | Build from scratch | Complete, certified | Complete, certified |
| Time to working AS | 6-12 months | 2-4 weeks | 1-2 weeks (Keycloak) / 2-4 weeks (Spring) |
| `act`/`may_act` claims | Custom JWT claims | Custom JWT claims | Custom JWT claims |
| Runtime performance | Best | Adequate | Adequate |
| Operational overhead | Lowest | Low-Medium | Medium-High (JVM) |
| Security audit confidence | Low (custom code) | Medium (established library) | High (Keycloak has been audited) |

---

## 8. Notable Projects

### Kanidm (Rust)
- **URL**: https://github.com/kanidm/kanidm
- **Stars**: ~2.6k
- **Status**: Active development, production use
- **Relevance**: Only production Rust identity platform. Does OAuth2/OIDC but is a complete IdM, not a library. No RFC 8693 support.

### Ory Hydra (Go)
- **URL**: https://github.com/ory/hydra
- **Status**: OpenID Certified, production-grade, used by OpenAI and others
- **Relevance**: The "what good looks like" benchmark for open-source AS. Written in Go. Extensible grant types through Fosite library. Does not natively support RFC 8693 but could be extended.

### ZITADEL (Go)
- **URL**: https://github.com/zitadel/zitadel
- **Status**: API-first, event-sourced architecture
- **Relevance**: Modern Go-based identity platform. OpenID Certified.

### Authelia (Go)
- **URL**: https://github.com/authelia/authelia
- **Status**: OpenID Certified (recent)
- **Relevance**: Authentication/authorization portal. Not a full AS -- acts as a reverse proxy companion. Written in Go.

### Authentik (Python)
- **URL**: https://github.com/goauthentik/authentik
- **Status**: Active, popular in homelabs and SMBs
- **Relevance**: Full IdP with flow-based UI. Written in Python/Django.

### CNCF Landscape
There are **no Rust-based identity/auth projects** in the CNCF landscape. The identity space in CNCF is dominated by Go projects (Dex, Keycloak adapters, SPIFFE/SPIRE). This is a significant signal about where the identity community's engineering gravity is.

---

## 9. Honest Assessment and Recommendation

### The bottom line

**Rust is not the right choice for building an OAuth 2.0 / OIDC Authorization Server with RFC 8693 Token Exchange today (February 2026).** The ecosystem gap is too large for the specific use case.

### Why not Rust

1. **You would be building an OIDC Provider from scratch.** There is no library that provides the OIDC Provider layer. This means implementing discovery, JWKS, ID tokens, userinfo, token introspection, and all the edge cases that existing certified libraries handle correctly. This is not a weekend project -- it is months of engineering and security review.

2. **RFC 8693 does not exist in Rust.** Every other mature language ecosystem has at least one implementation to reference. In Rust, you are starting from zero. The `act`/`may_act` claim semantics, delegation chain validation, and chain-splicing prevention would all be novel Rust code.

3. **You lose the security advantage by writing custom crypto-adjacent code.** Rust's memory safety is valuable, but an AS's security depends far more on *correct protocol implementation* than on memory safety. A custom-built, unaudited AS in Rust is less secure than using a battle-tested, OpenID-Certified implementation in Go or Java.

4. **The identity/auth community is not in Rust.** When you need to discuss edge cases, file conformance issues, or get security review, the experts are in the Java, Go, and .NET communities. The Rust identity ecosystem has Kanidm and oxide-auth's single maintainer.

### When Rust *would* make sense for identity

- **Token validation libraries**: Building a high-performance token validation sidecar (e.g., for service mesh) where you validate JWTs at extreme throughput.
- **Cryptographic modules**: DPoP proof generation/validation, JWE operations, key management HSM interfaces.
- **Edge/embedded AS**: If you need an AS that runs in a 5MB container at the edge with sub-millisecond cold start.
- **In 3-5 years**: If the Rust identity ecosystem matures to the point where an OIDC Provider library exists, Rust becomes a strong candidate.

### Recommended approach for oidc-loki

For the oidc-loki project's RFC 8693 Token Exchange needs:

1. **Primary AS**: Use an established platform (Keycloak 26.2+ for standard RFC 8693, or extend node-oidc-provider/Spring Authorization Server).
2. **Rust components**: Consider Rust for specific high-performance or security-critical modules (DPoP validation, token introspection proxy, cryptographic operations) that can be deployed as sidecars or libraries.
3. **Future rewrite**: If the project succeeds and performance/deployment characteristics of Rust become compelling, a future rewrite becomes more feasible as the ecosystem matures.

This hybrid approach gets you the protocol correctness and certification of established platforms while reserving Rust for where it adds genuine value.

---

## Sources

- [Kanidm - GitHub](https://github.com/kanidm/kanidm)
- [oxide-auth - GitHub](https://github.com/HeroicKatora/oxide-auth)
- [oxide-auth - crates.io](https://crates.io/crates/oxide-auth)
- [jsonwebtoken - GitHub](https://github.com/Keats/jsonwebtoken)
- [josekit - docs.rs](https://docs.rs/josekit)
- [openidconnect-rs - GitHub](https://github.com/ramosbugs/openidconnect-rs)
- [oauth2-rs - GitHub](https://github.com/ramosbugs/oauth2-rs)
- [Axum - GitHub](https://github.com/tokio-rs/axum)
- [config crate - crates.io](https://crates.io/crates/config)
- [Ory Hydra - GitHub](https://github.com/ory/hydra)
- [auth-framework - GitHub](https://github.com/ciresnave/auth-framework)
- [rustls - GitHub](https://github.com/rustls/rustls)
- [ring - docs.rs](https://docs.rs/ring)
- [Keycloak Standard Token Exchange Announcement](https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2)
- [Spring Authorization Server Token Exchange](https://spring.io/blog/2024/03/19/token-exchange-support-in-spring-security-6-3-0-m3/)
- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [OAuth Libraries for Rust](https://oauth.net/code/rust/)
- [Rust Web Frameworks Comparison](https://dev.to/leapcell/rust-web-frameworks-compared-actix-vs-axum-vs-rocket-4bad)
- [Leptos - GitHub](https://github.com/leptos-rs/leptos)
- [Authelia - GitHub](https://github.com/authelia/authelia)
- [ZITADEL OIDC - GitHub](https://github.com/zitadel/oidc)
