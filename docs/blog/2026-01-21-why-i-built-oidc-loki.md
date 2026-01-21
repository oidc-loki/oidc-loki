---
title: Why I Built a Malicious Identity Provider (And Why You Still Need One in 2026)
published: true
tags: security, oauth, oidc, testing
cover_image:
---

## "Aren't JWT Vulnerabilities a Solved Problem?"

That's what I thought too. Then I looked at 2025's CVE list:

- **CVE-2025-27370/27371** - Spec-level JWT audience validation flaws in OpenID Connect itself
- **CVE-2025-31123** - Zitadel (popular open-source IdP) accepted expired JWT signing keys
- **CVE-2024-54150** - Algorithm confusion in cjwt (C library)
- **CVE-2023-48223** - Algorithm confusion in fast-jwt (Node.js)

These aren't legacy systems. Zitadel and fast-jwt are modern, actively maintained projects. The pattern repeats every year.

## Why This Keeps Happening

1. **New libraries** - Every language gets new JWT/OIDC implementations
2. **Custom auth** - Enterprises build bespoke identity layers
3. **Spec complexity** - OIDC has dozens of optional parameters to validate
4. **Happy-path testing** - Libraries test against compliant IdPs, not malicious ones

## The Problem OIDC-Loki Solves (And Doesn't)

Let's be specific. OIDC vulnerabilities fall into two categories:

**Client-side validation bugs** (OIDC-Loki can help):
- Accepting `alg: none` tokens
- Algorithm confusion (RS256→HS256)
- Not validating `iss`, `aud`, `exp`, `nbf` claims
- Accepting tokens meant for other applications

**Server-side / IdP bugs** (OIDC-Loki can't help):
- IdP leaking secrets (like CVE-2025-59363 - OneLogin)
- IdP misconfigurations
- Server-side injection vulnerabilities

OIDC-Loki tests your **client** by giving it bad tokens. It can't find bugs in your IdP.

| 2024-2025 CVE | Type | OIDC-Loki Helps? |
|---------------|------|------------------|
| CVE-2025-27370/27371 | Client validation | Yes |
| CVE-2024-54150 | Client validation | Yes |
| CVE-2023-48223 | Client validation | Yes |
| CVE-2025-31123 | Key lifecycle | Partially |
| CVE-2025-59363 | Server-side leak | No |

That's 3-4 out of 5 recent CVEs that proper client testing could have caught.

## Chaos Engineering for Identity

We chaos-test everything else:
- Databases → Chaos Monkey
- Networks → tc netem, Toxiproxy
- APIs → fault injection

Why not identity providers?

## Introducing OIDC-Loki

A fully compliant OIDC provider that misbehaves on command:

```typescript
const session = loki.createSession({
  name: "security-test",
  mischief: ["alg-none", "key-confusion", "audience-confusion"]
});
// Every token from this session is now malicious
```

## What It Tests

| Attack | What It Catches |
|--------|-----------------|
| `alg-none` | Client accepts unsigned tokens |
| `key-confusion` | Client vulnerable to RS256→HS256 |
| `audience-confusion` | Client accepts tokens for other apps |
| `issuer-confusion` | Client accepts tokens from wrong IdP |
| `temporal-tampering` | Client accepts expired/future tokens |

15 attack plugins total, each mapped to RFC/CWE references.

## Example: Testing a Go Client

```go
// Create mischief session
session := createSession("alg-none-test", []string{"alg-none"})

// Get malicious token from Loki
token := getToken(session.ID)

// Your client SHOULD reject this
err := validateToken(token)
if err == nil {
    t.Fatal("VULNERABLE: Client accepted unsigned token!")
}
```

Full examples in Go, Python, Rust, and Java included in the repo.

## The Audit Trail

Every attack is logged with compliance references:

```json
{
  "plugin": "alg-none",
  "spec": { "rfc": "RFC 8725", "cwe": "CWE-327" },
  "evidence": { "originalAlg": "RS256", "newAlg": "none" }
}
```

## Who Should Use This?

- **Library authors** - Test your JWT/OIDC validation logic
- **Security teams** - Verify client apps reject malicious tokens
- **Pentesters** - Systematic coverage of OIDC attack surface
- **Compliance** - Document which attacks were tested

## Who Shouldn't Use This?

If you're trying to find bugs in your IdP (Okta, Auth0, Keycloak, etc.), this isn't the tool. OIDC-Loki tests consumers of identity, not providers.

## Try It

```bash
npm install oidc-loki
```

GitHub: [github.com/cbchhaya/oidc-loki](https://github.com/cbchhaya/oidc-loki)

Examples: [github.com/cbchhaya/oidc-loki/tree/main/examples](https://github.com/cbchhaya/oidc-loki/tree/main/examples)

---

*OIDC-Loki is for authorized security testing only.*
