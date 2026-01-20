# Security Policy

## Purpose of This Tool

OIDC-Loki is a **security testing tool** designed to help developers test their OIDC client implementations against malformed and malicious tokens. It intentionally produces spec-violating outputs for defensive testing purposes.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in OIDC-Loki itself (not the intentional "mischief" behaviors), please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email cbc.devel@gmail.com or use [GitHub's private vulnerability reporting](https://github.com/cbchhaya/oidc-loki/security/advisories/new)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Security Considerations for Users

### This Tool is Dangerous by Design

OIDC-Loki produces:
- Tokens with `alg: "none"` (unsigned)
- Tokens signed with wrong algorithms (key confusion)
- Tokens with manipulated timestamps
- Other spec-violating responses

### Safe Usage Guidelines

1. **Never run in production** - This tool is for testing only
2. **Use isolated environments** - Run in containers or VMs
3. **Never use real credentials** - Use test-only client IDs and secrets
4. **Network isolation** - Don't expose Loki to untrusted networks
5. **Audit trail** - Review the mischief ledger after testing

### What We Don't Consider Vulnerabilities

The following are intentional features, not bugs:
- Producing unsigned tokens
- Producing tokens with wrong algorithms
- Producing expired or not-yet-valid tokens
- Any behavior controlled by mischief plugins

## Dependencies

We monitor our dependencies for known vulnerabilities using:
- GitHub Dependabot
- npm audit
- CodeQL scanning

## Acknowledgments

We appreciate security researchers who help keep OIDC-Loki safe for its intended use case of defensive security testing.
