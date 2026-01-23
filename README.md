# OIDC-Loki

> **NOTICE:** This project is provided for demonstration and educational purposes only. It may NOT be used for commercial purposes. This software comes with NO WARRANTIES of any kind. Use at your own risk.

[![CI](https://github.com/oidc-loki/oidc-loki/actions/workflows/ci.yml/badge.svg)](https://github.com/oidc-loki/oidc-loki/actions/workflows/ci.yml)
[![CodeQL](https://github.com/oidc-loki/oidc-loki/actions/workflows/codeql.yml/badge.svg)](https://github.com/oidc-loki/oidc-loki/security/code-scanning)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/oidc-loki/oidc-loki/badge)](https://securityscorecards.dev/viewer/?uri=github.com/oidc-loki/oidc-loki)
[![Coverage](https://img.shields.io/badge/coverage-82%25-brightgreen)](https://github.com/oidc-loki/oidc-loki)
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)

**The Bad Identity Provider** - Security Chaos Engineering for OIDC

OIDC-Loki is a programmable OIDC identity provider that intentionally violates specifications to test how resilient your OIDC client implementations are against malformed, malicious, or spec-violating responses.

## Why?

Most OIDC client libraries are tested against well-behaved identity providers. But what happens when:

- The IdP returns a token with `alg: "none"` and no signature?
- The token is signed with HMAC using the public key (key confusion attack)?
- Token timestamps are manipulated (expired, not-yet-valid)?
- Responses are delayed to test timeout handling?

OIDC-Loki helps you answer these questions by providing a fully functional OIDC provider that can be configured to misbehave in specific, controlled ways.

## Features

- **Full OIDC Provider**: Built on `oidc-provider`, supports standard flows
- **Mischief Plugins**: Modular attacks that can be enabled per-session
- **Session-Based Testing**: Isolate test scenarios with unique session IDs
- **Detailed Ledger**: Track exactly what mischief was applied and when
- **Library & Standalone**: Use programmatically in tests or run as a service
- **Custom Plugins**: Extend with your own attack scenarios
- **Persistence**: SQLite storage for sessions and audit trails

## Quick Start

### Installation

```bash
npm install oidc-loki
```

### Library Usage (Recommended for Testing)

```typescript
import { Loki } from "oidc-loki";
import { describe, it, beforeAll, afterAll, expect } from "vitest";

describe("My OIDC Client Security", () => {
  let loki: Loki;

  beforeAll(async () => {
    loki = new Loki({
      server: { port: 9000, host: "localhost" },
      provider: {
        issuer: "http://localhost:9000",
        clients: [
          {
            client_id: "my-app",
            client_secret: "secret",
            grant_types: ["client_credentials"],
          },
        ],
      },
      persistence: { enabled: false, path: "" },
    });
    await loki.start();
  });

  afterAll(async () => {
    await loki.stop();
  });

  it("should reject alg:none tokens", async () => {
    // Create a session with alg-none attack enabled
    const session = loki.createSession({
      name: "alg-none-test",
      mode: "explicit",
      mischief: ["alg-none"],
    });

    // Get a malicious token from Loki
    const response = await fetch("http://localhost:9000/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${btoa("my-app:secret")}`,
        "X-Loki-Session": session.id, // Links request to mischief session
      },
      body: "grant_type=client_credentials",
    });

    const { access_token } = await response.json();

    // Verify the token has alg:none (Loki applied mischief)
    const [header] = access_token.split(".");
    const decoded = JSON.parse(atob(header));
    expect(decoded.alg).toBe("none");

    // Now test YOUR client - it should reject this token!
    // await expect(myClient.validateToken(access_token)).rejects.toThrow();
  });
});
```

### Standalone Server

```bash
# Using environment variables
LOKI_PORT=3000 LOKI_ISSUER=http://localhost:3000 npm run dev

# Or with npx (after publishing)
npx oidc-loki
```

Then use the Admin API to create sessions:

```bash
# Create a mischief session
curl -X POST http://localhost:3000/admin/sessions \
  -H "Content-Type: application/json" \
  -d '{"name": "chaos-test", "mode": "explicit", "mischief": ["alg-none"]}'

# Response: {"sessionId": "sess_abc123xyz"}

# Use the session ID in token requests
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'test-client:test-secret' | base64)" \
  -H "X-Loki-Session: sess_abc123xyz" \
  -d "grant_type=client_credentials"
```

## Built-in Mischief Plugins

Each plugin targets a specific vulnerability class, complete with RFC/CWE references for compliance testing:

### Critical Severity - Signature & Identity Attacks

| Plugin | Attack Vector | Spec Reference |
|--------|---------------|----------------|
| `alg-none` | Removes JWT signature entirely | RFC 8725, CWE-327 |
| `key-confusion` | RS256→HS256 key confusion attack | RFC 8725, CWE-327 |
| `issuer-confusion` | Spoofs the `iss` claim to test issuer validation | RFC 7519 §4.1.1, CWE-290 |
| `audience-confusion` | Manipulates `aud` claim for cross-service token abuse | RFC 7519 §4.1.3, CWE-284 |
| `subject-manipulation` | Manipulates `sub` claim for identity spoofing | RFC 7519 §4.1.2, CWE-287 |

### High Severity - Key & Flow Attacks

| Plugin | Attack Vector | Spec Reference |
|--------|---------------|----------------|
| `kid-manipulation` | Manipulates key ID header for key confusion | RFC 7517 §4.5, CWE-347 |
| `temporal-tampering` | Expired/future token timestamps | RFC 7519 §4.1.4, CWE-613 |
| `nonce-bypass` | Removes or replays nonce for session fixation | OIDC Core §3.1.3.7, CWE-384 |
| `state-bypass` | Manipulates state/azp for CSRF attacks | RFC 6749 §10.12, CWE-352 |
| `pkce-downgrade` | Tests PKCE handling and auth context | RFC 7636, CWE-345 |

### Medium Severity - Resilience Testing

| Plugin | Attack Vector | Spec Reference |
|--------|---------------|----------------|
| `latency-injection` | Response delay for timeout testing | OIDC Core §3.1.2.1 |

### Why Plugins?

Plugins are modular attack scenarios that can be:
- **Composed**: Enable multiple attacks per session for complex scenarios
- **Audited**: Every mutation is logged with RFC/CWE references
- **Extended**: Write custom plugins for vendor-specific or compliance testing
- **Randomized**: Use `random` or `shuffled` modes for fuzzing

## Session Modes

- **explicit**: You specify exactly which plugins to activate
- **random**: Randomly applies one plugin from your list per request
- **shuffled**: Cycles through plugins in random order, one per request

## Documentation

- [Testing Guide](./docs/testing-guide.md) - How to test your OIDC clients
- [Library Usage](./docs/library-usage.md) - Detailed API reference
- [Plugin Development](./docs/plugin-development.md) - Create custom mischief plugins
- [Client Examples](./examples/README.md) - Example clients in Go, Python, Rust, and Java
- [Blog: Why I Built OIDC-Loki](./docs/blog/2026-01-21-why-i-built-oidc-loki.md) - Background and motivation

## Admin API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/admin/sessions` | GET | List all sessions |
| `/admin/sessions` | POST | Create a new session |
| `/admin/sessions/:id` | GET | Get session details |
| `/admin/sessions/:id` | DELETE | Delete a session |
| `/admin/sessions/:id/ledger` | GET | Get full mischief ledger |
| `/admin/plugins` | GET | List available plugins |
| `/admin/plugins/:id` | GET | Get plugin details |
| `/admin/reset` | POST | Purge all sessions |

## Security Considerations

OIDC-Loki is a **security testing tool**. It intentionally produces malformed and potentially dangerous tokens.

- **Never** run in production
- **Never** use real user credentials
- **Always** run in isolated test environments
- Use for defensive testing only

## Contributing

Contributions welcome! Areas of interest:

- New mischief plugins for other OIDC/OAuth2 attack vectors
- Integration with popular testing frameworks
- Additional output formats (SARIF, etc.)

## License

CC BY-NC-SA 4.0

This project is for demonstration and educational purposes only. Commercial use is prohibited. See [LICENSE](./LICENSE) for details.

## Acknowledgments

This project was built through human-AI collaboration using [Claude Code](https://claude.ai/code). The architecture, implementation, documentation, and test suite were developed iteratively through pair programming between a human developer and Claude (Anthropic's AI assistant).

---

*"In Norse mythology, Loki is known as a trickster god. OIDC-Loki brings that same energy to your identity infrastructure testing."*
