# Agentic OIDC Security Threat Analysis

This document provides an independent threat analysis of emerging OpenID Connect (OIDC) and OAuth 2.0 standards, with a specific focus on their application in environments with AI and autonomous agents.

## 1. Token Exchange (RFC 8693)

Token Exchange allows one party (an "actor") to exchange a token representing a user (the "subject") for a new token, often for a different audience (resource). This is the foundation of delegation.

-   **Misconfigurations:**
    -   **Lax Token Type Validation:** Authorization Server (AS) permits exchange of incompatible token types (e.g., exchanging a refresh token for an access token with different claims) without proper validation.
    -   **Improper `act` Claim Handling:** The AS fails to correctly construct the `act` (actor) claim, potentially omitting the delegation chain or representing the final actor as the original subject.
    -   **Audience Restriction Bypass:** The AS does not validate that the `actor_token` is intended for the token exchange endpoint, allowing it to be used in unintended contexts.
    -   **Privilege Escalation by Default:** The AS issues a new token with scopes or claims exceeding those of the original `subject_token`, rather than requiring an explicit request for elevated privileges.

-   **Attack Vectors:**
    -   **Impersonation:** An attacker with a low-privilege token can exchange it for a token that incorrectly represents them as the original subject, inheriting their full permissions.
    -   **Privilege Escalation:** A compromised actor exchanges a subject's `read-only` token and receives a `read-write` token due to a permissive AS policy.
    -   **Delegation Hijacking:** A legitimate but compromised actor in a delegation chain performs unauthorized actions on behalf of the subject.

-   **AI-Agent-Specific Threats:**
    -   An AI agent, acting as a delegate, could be manipulated by a malicious user's prompt into exchanging a token for a new one with a broader audience or scope, effectively "tricking" the agent into accessing unintended resources.
    -   An agent with broad token exchange permissions becomes a high-value target for attackers, as compromising it would allow them to mint delegated tokens for various services.

-   **Severity:** High to Critical. Impersonation and privilege escalation can lead to complete account takeover or unauthorized data access.

-   **`oidc-loki` Plugin Ideas:**
    -   **`token-exchange-impersonation`**: A plugin that simulates an actor exchanging a subject's token where the AS is configured to improperly grant the new token claims as if it were from the subject directly, bypassing the `act` claim.
    -   **`token-exchange-privesc`**: A plugin that sends a `subject_token` with `scope=read` and an `actor_token` with `scope=read`, and tests if the AS can be manipulated into issuing a new token with `scope=write`.

## 2. `may_act` Claim

The `may_act` claim in a token specifies which actors are permitted to act on behalf of the subject.

-   **Misconfigurations:**
    -   **`may_act` Ignored:** The AS doesn't enforce the `may_act` claim, allowing any actor to exchange the token.
    -   **Inconsistent Validation:** A Resource Server (RS) receives a token with an `act` claim but doesn't validate it against the `may_act` claim from the original token introspection.
    -   **Overly Permissive `may_act`:** Using wildcards or broad categories in the `may_act` claim in a production environment, defeating its purpose.

-   **Attack Vectors:**
    -   **Unauthorized Delegation:** An attacker steals a user's token containing a `may_act` claim and uses their own malicious client as an actor, which the AS should have denied.
    -   **Actor Spoofing:** An attacker registers a malicious client and tricks a user into delegating access, which would have been prevented if `may_act` was properly restricted.

-   **AI-Agent-Specific Threats:**
    -   An AI agent's identity could be used to act on behalf of a user without their explicit consent if the `may_act` claim is not strictly enforced.
    -   A user could be tricked into authorizing an action where the `may_act` claim is populated with a malicious AI agent, granting it delegated authority.

-   **Severity:** Medium to High. Circumventing explicit delegation permissions can lead to unauthorized actions.

-   **`oidc-loki` Plugin Ideas:**
    -   **`may-act-violation`**: Initiate a token exchange where the `actor_token`'s `client_id` is explicitly not listed in the `subject_token`'s `may_act` claim. The test passes if the AS correctly denies the exchange.

## 3. `requested_actor` Parameter

This parameter in an authorization request allows a client to request a specific actor to be included in the delegation chain.

-   **Misconfigurations:**
    -   **Unvalidated `requested_actor`:** The AS honors the `requested_actor` parameter without verifying that the subject has authorized that actor for delegation.
    -   **Forced Parameter Honor:** The AS processes the `requested_actor` parameter even when the feature is disabled globally or for a specific client.

-   **Attack Vectors:**
    -   **Forced Actor Selection:** An attacker can forge an authorization request, injecting a `requested_actor` parameter that points to a compromised or malicious actor, thus forcing a vulnerable delegation.

-   **AI-Agent-Specific Threats:**
    -   A user could be socially engineered into clicking a link that initiates an authorization request. This request could contain a hidden `requested_actor` parameter pointing to a malicious AI agent, which the user unknowingly authorizes.

-   **Severity:** Medium. The attack requires user interaction but can lead to a powerful, authorized man-in-the-middle.

-   **`oidc-loki` Plugin Ideas:**
    -   **`requested-actor-unauthorized`**: The plugin forges an authorization request containing a `requested_actor` that the user has not pre-authorized. The test checks if the AS proceeds with the flow and includes the unauthorized actor in the `act` claim.

## 4. Chained Delegation

This refers to multi-hop delegation, where `actor1` acts on behalf of a subject, `actor2` acts on behalf of `actor1`, and so on. The `act` claim becomes nested.

-   **Misconfigurations:**
    -   **Unbounded Chain Depth:** The AS does not enforce a maximum depth for the delegation chain, allowing for excessively long or infinite chains.
    -   **Incomplete Chain Validation:** Intermediate actors do not fully validate the entire nested `act` claim of the incoming token before adding themselves to the chain.
    -   **Poor `act` Claim Parsing:** The final Resource Server fails to parse or validate a complex, multi-level `act` claim, potentially ignoring deeper actors.

-   **Attack Vectors:**
    -   **Denial of Service (DoS):** An attacker creates a token with a deeply nested or circular `act` claim, causing significant CPU and memory consumption at the Resource Server during parsing, leading to DoS.
    -   **Attribution Masking:** Extremely long chains make it practically impossible to audit or trace an action back to the original initiator, hiding malicious activity.
    -   **Chain-of-Custody Bypass:** A compromised actor in the middle of a chain could "break" the chain by exchanging the token for a new one that omits the prior actors.

-   **AI-Agent-Specific Threats:**
    -   A chain of AI agents could be constructed where each agent performs a small, seemingly benign task, but the cumulative effect is malicious. The long chain obscures the overall intent and origin.
    -   An AI agent could be tricked via prompt injection into adding a malicious "sub-agent" to the delegation chain, which then performs unauthorized actions.

-   **Severity:** Medium to High. DoS is a real risk, and the loss of audibility can hide critical security incidents.

-   **`oidc-loki` Plugin Ideas:**
    -   **`delegation-chain-depth-limit`**: A plugin that repeatedly performs token exchanges to create a delegation chain longer than a defined policy limit, checking if the AS eventually rejects the request.
    -   **`act-claim-parsing-fuzz`**: A plugin that generates tokens with malformed, deeply nested, or recursive `act` claims and sends them directly to a resource server to test for parsing vulnerabilities.

## 5. OAuth 2.0 for AI Agents

This conceptual area covers the unique patterns and risks of AI/LLM agents acting as OAuth clients.

-   **Misconfigurations:**
    -   **Static, Long-Lived Tokens:** Issuing agents static, long-lived access tokens instead of using a proper grant flow to acquire short-lived ones.
    -   **Overly Broad Permissions:** Granting an agent `*.*` or similarly broad scopes, violating the principle of least privilege.
    -   **Lack of Proof-of-Possession:** Allowing agents to use simple bearer tokens, which are vulnerable to theft and replay. DPoP or other PoP mechanisms should be used.

-   **Attack Vectors:**
    -   **Confused Deputy:** This is the primary threat. An attacker uses prompt injection to trick an AI agent into performing a privileged action that the attacker is not authorized to perform directly. The agent misuses its legitimate authority.
    -   **Agent Credential Exfiltration:** The agent's client secrets, private keys, or active tokens are stolen from its memory or storage, allowing the attacker to impersonate it directly.

-   **AI-Agent-Specific Threats:**
    -   The agent's natural language interface becomes a primary attack surface for manipulating its authorized actions.
    -   Agents that can autonomously request new scopes or permissions can be tricked into escalating their own privileges.
    -   Multi-agent systems (MCPs) can be attacked by compromising one agent and using it to send malicious instructions to others.

-   **Severity:** High to Critical. A compromised or confused agent can become a powerful tool for an attacker.

-   **`oidc-loki` Plugin Ideas:**
    -   **`agent-confused-deputy-simulation`**: This would require a mock agent endpoint. The plugin would send carefully crafted "prompts" (e.g., API requests simulating user input) to the mock agent, testing if it can be induced to call a high-privilege API with data it shouldn't have access to.

## 6. OIDC Federation (RFC 9278)

OIDC Federation enables dynamic, large-scale trust establishment between entities without pairwise, manual configuration.

-   **Misconfigurations:**
    -   **Insecure Trust Anchors:** The root keys for the federation are not properly secured, or development/testing anchors are used in production.
    -   **Ignoring Metadata Policy:** A federation entity accepts metadata from another entity that violates the established policies of the federation.
    -   **Improper Signature Validation:** Failing to validate the signatures on fetched federation metadata, allowing for tampering.

-   **Attack Vectors:**
    -   **Trust Anchor Compromise:** If an attacker compromises a federation's trust anchor, they can sign malicious metadata, effectively impersonating any entity within that federation or injecting new, malicious entities.
    -   **Metadata Poisoning:** An attacker performs a man-in-the-middle attack during metadata discovery to inject a malicious `jwks_uri` or other endpoint, redirecting authentication flows through attacker-controlled infrastructure.

-   **AI-Agent-Specific Threats:**
    -   An AI agent with the capability to dynamically join federations could be tricked into joining a malicious one, exposing its credentials or user data.
    -   An attacker could create a fake federation designed to look legitimate, luring autonomous agents into establishing trust and then exploiting them.

-   **Severity:** Critical. A compromised federation can lead to a systemic, large-scale loss of trust across many organizations.

-   **`oidc-loki` Plugin Ideas:**
    -   **`federation-metadata-poisoning`**: A plugin that acts as a client, but during the federation metadata discovery process, it attempts to use a tampered or malicious metadata endpoint to see if the client's validation logic can be bypassed.

## 7. DPoP (RFC 9449)

Demonstrating Proof-of-Possession (DPoP) binds an access token to a specific private key, preventing stolen bearer tokens from being replayed.

-   **Misconfigurations:**
    -   **`jti` Nonce Ignored:** The AS or RS does not track the `jti` (JWT ID) claim in DPoP proofs, allowing an attacker who steals both a token and its proof to replay the request.
    -   **`htu`/`htm` Validation Failure:** The server does not validate that the HTTP target URI (`htu`) and method (`htm`) in the proof match the current request, allowing a proof to be used for unintended API endpoints.
    -   **No `cnf` Claim:** The AS issues an access token without a `cnf` (confirmation) claim, meaning the token is not actually bound to the DPoP key and can be used as a simple bearer token.

-   **Attack Vectors:**
    -   **Bound Token Replay:** An attacker on the client-side (e.g., via browser extension) or on the wire (with TLS break) steals a DPoP-bound token and its corresponding proof JWT, then replays them successfully because the server isn't checking the `jti`.
    -   **Proof Substitution:** An attacker uses a valid proof intended for `GET /api/read` to make a request to `POST /api/delete`.

-   **AI-Agent-Specific Threats:**
    -   An AI agent's process memory could be scraped to steal the DPoP private key. If the agent is compromised, the attacker can generate valid proofs for any stolen tokens.
    -   An agent that handles multiple user accounts could be tricked into using the wrong DPoP key for a given user's token, causing authorization failures or security bypasses.

-   **Severity:** Medium. DPoP is a mitigation. Its failure removes a layer of security but doesn't create a new vulnerability on its own. The primary threat remains token theft.

-   **`oidc-loki` Plugin Ideas:**
    -   **`dpop-proof-replay`**: The plugin makes a valid API call with DPoP, captures the proof, and immediately sends the exact same request and proof again, checking to see if the server fails to reject it.
    -   **`dpop-htu-mismatch`**: The plugin generates a valid DPoP proof but for a different URI (`htu` claim) and sends it to the target endpoint to test if the mismatch is detected.

## 8. Rich Authorization Requests (RAR, RFC 9396)

RAR allows a client to request fine-grained permissions using a structured `authorization_details` object instead of simple scopes.

-   **Misconfigurations:**
    -   **AS Ignores `authorization_details`:** The AS disregards the RAR parameter and falls back to issuing tokens based on pre-configured, broad scopes.
    -   **RS Incompatibility:** The Resource Server does not understand or is not configured to parse the `authorization_details` claim in the access token, effectively ignoring the fine-grained permissions.
    -   **Complex Object Parsing Errors:** The AS or RS has a buggy parser for the `authorization_details` JSON structure, leading to incorrect interpretation of the requested permissions.

-   **Attack Vectors:**
    -   **Privilege Creep:** If RAR is not strictly enforced, clients will consistently receive tokens with more permissions than they actually need for a given operation, widening the attack surface if the client is compromised.
    -   **Request Ambiguity:** An attacker might craft an ambiguous `authorization_details` object, hoping a buggy parser will interpret it in a more permissive way than intended.

-   **AI-Agent-Specific Threats:**
    -   An AI agent, in its attempt to be helpful, might request overly broad permissions via RAR. A well-configured AS should deny this, but a misconfigured one might grant it, turning the agent into an over-privileged entity.

-   **Severity:** Low to Medium. This is primarily about the absence of a security hardening feature. It leads to a less secure posture but is not a direct, exploitable vulnerability itself.

-   **`oidc-loki` Plugin Ideas:**
    -   **`rar-ignored`**: The plugin sends an authorization request with a highly specific `authorization_details` object (e.g., access to one specific record ID) and then introspects the resulting token to see if broader, non-requested scopes were granted instead.

## 9. Grant Negotiation and Authorization Protocol (GNAP)

Intended as a successor to OAuth 2.0, GNAP is a more flexible but also more complex protocol.

-   **Misconfigurations:**
    -   **Insecure Client-to-AS Channel:** Communication between the client and AS must be secured, but misconfigurations could lead to downgrade attacks or interception.
    -   **Improper Grant Request Validation:** The AS may not properly validate the complex `access` array in the grant request, potentially allowing a client to request conflicting or insecure combinations of access rights.
    -   **Interaction URL Vulnerabilities:** The `interact` response parameters (e.g., user code, interaction URL) could be leaked or manipulated if not handled correctly.

-   **Attack Vectors:**
    -   **Grant Request Injection:** An attacker could intercept and modify the grant request from a legitimate client to the AS, adding more privileges or changing callbacks before it's sent.
    -   **Continuation URI Hijacking:** If an attacker can predict or capture the `continue_uri`, they might be able to inject a fake response to the client.

-   **AI-Agent-Specific Threats:**
    -   The complexity of GNAP could lead to implementation errors in AI agents that act as GNAP clients, making them vulnerable to protocol-level attacks.
    -   The asynchronous, multi-step nature of GNAP grants provides a larger window for an attacker to interfere with an agent's authorization flow, especially if the agent's state management is weak.

-   **Severity:** High. As a foundational authorization protocol, implementation flaws can lead to severe security breaches.

-   **`oidc-loki` Plugin Ideas:**
    -   **`gnap-grant-modification`**: A plugin that acts as a malicious client, crafting a complex GNAP grant request with ambiguous or conflicting items in the `access` array to test for parsing and logic flaws at the AS.

## 10. Step-up Authentication (RFC 9470)

This standard formalizes how to request that an authentication event be "stepped up" with a stronger mechanism (e.g., MFA).

-   **Misconfigurations:**
    -   **ACR Inflation:** An AS issues a token with a high-trust Authentication Context Class Reference (`acr`) claim (e.g., `https://refeds.org/profile/mfa`) without actually having performed the corresponding authentication.
    -   **Unverified ACR Trust:** A Resource Server trusts the `acr` claim from any AS, including potentially malicious or low-trust ones, without validating the issuer.
    -   **`claims` Parameter Ignored:** The AS ignores the `acr` value requested in the `claims` parameter of the authorization request.

-   **Attack Vectors:**
    -   **ACR Spoofing/Bypass:** A compromised AS or a malicious client in a weak flow could forge a token with a high-trust `acr` value. The RS then trusts this claim and incorrectly grants access to a resource that should have been protected by MFA.
    -   **Session Fixation with Stepped-Up ACR:** An attacker logs in, performs a step-up action, and then tricks the victim into using that same session, effectively bypassing the MFA requirement for the victim's actions.

-   **AI-Agent-Specific Threats:**
    -   An AI agent that orchestrates a user authentication flow could be tricked into believing a step-up has occurred when it hasn't (e.g., by a malicious browser extension spoofing a callback). The agent then proceeds, holding a token that is incorrectly believed to be high-trust.
    -   In a delegated chain, an agent may fail to propagate the `acr` requirement to the next actor, resulting in a "step-down" of security context along the chain.

-   **Severity:** High to Critical. Bypassing strong authentication mechanisms like MFA is a critical failure that can lead to full account compromise.

-   **`oidc-loki` Plugin Ideas:**
    -   **`step-up-acr-spoof`**: A plugin that modifies an authorization request to ask for a specific `acr` value (e.g., MFA) but intentionally completes only a single-factor flow. It then checks if the AS incorrectly issues a token containing the requested high-trust `acr` value.
    -   **`step-up-claim-injection`**: A plugin that takes a valid, single-factor token and attempts to use it at a resource server that expects an MFA-protected token, testing if the RS fails to enforce the ACR requirement.
