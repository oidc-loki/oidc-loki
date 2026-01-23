# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in OIDC-Loki, please report it responsibly.

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Use GitHub's [private vulnerability reporting](https://github.com/oidc-loki/oidc-loki/security/advisories/new)
3. Include the following in your report:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 90 days

### Security Measures

This project implements the following security practices:

- **Dependency Scanning**: Automated via Dependabot and dependency-review-action
- **Static Analysis**: CodeQL analysis on all PRs and main branch
- **Supply Chain Security**: OpenSSF Scorecard monitoring
- **Pinned Dependencies**: All GitHub Actions pinned to specific commit SHAs

## Scope

This security policy applies to:
- The OIDC-Loki core library
- Built-in mischief plugins
- CLI tools
- Documentation

### Out of Scope

- Third-party plugins (report to plugin maintainers)
- Issues in dependencies (report to upstream projects)

## Responsible Use

OIDC-Loki is a security testing tool designed for authorized testing only. Users are responsible for:

- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Using the tool ethically and responsibly

Misuse of this tool for unauthorized access or malicious purposes is strictly prohibited.
