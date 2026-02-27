# Token Exchange Security Posture Assessment Guide

> **Who this is for:** CISOs, compliance officers, security managers, and GRC teams who need to assess and report on their organization's token exchange security posture.
>
> **Difficulty:** Intermediate (security management perspective)

This guide maps splice-check's 28 attack vectors to industry frameworks (CWE, OWASP), provides risk scoring methodology, and offers remediation guidance suitable for executive reporting and compliance documentation.

## Executive Summary

OAuth 2.0 Token Exchange ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)) enables service-to-service delegation — a pattern increasingly critical for microservices and AI agent architectures. However, the specification contains gaps that allow **delegation chain splicing**: an attack where a compromised intermediary forges delegation relationships that were never authorized.

splice-check tests your Authorization Server against 28 attack vectors across 7 categories. Results can be used for:

- **Risk assessment** — Identify which delegation attack surfaces are exposed
- **Compliance evidence** — Document tested controls with RFC/CWE traceability
- **Remediation planning** — Prioritize fixes by severity and business impact
- **Vendor evaluation** — Compare AS products' delegation security

---

## Risk Scoring Methodology

### Severity Levels

| Severity | CVSS Range | Business Impact | SLA Recommendation |
|----------|------------|-----------------|---------------------|
| **Critical** | 9.0-10.0 | Unauthorized cross-chain delegation, complete trust boundary violation | Fix within 24-48 hours |
| **High** | 7.0-8.9 | Privilege escalation, audit trail corruption, revocation bypass | Fix within 1-2 weeks |
| **Medium** | 4.0-6.9 | Specification non-compliance, token bloat, reduced defense depth | Fix within 30 days |

### Posture Scoring

Calculate your delegation security posture score:

```
Score = (Tests Passed / (Total Tests - Tests Skipped)) * 100
```

| Score Range | Rating | Interpretation |
|-------------|--------|----------------|
| 95-100% | Excellent | Comprehensive delegation security controls |
| 85-94% | Good | Strong controls with minor gaps |
| 70-84% | Fair | Significant gaps requiring attention |
| Below 70% | Poor | Critical delegation attack surfaces exposed |

**Important:** Skipped tests (inconclusive) should be investigated separately — they may indicate configuration issues or missing endpoints rather than passing controls.

---

## CWE Mapping

Each attack vector maps to one or more Common Weakness Enumerations:

### Authorization & Access Control

| CWE | Description | splice-check Vectors |
|-----|-------------|---------------------|
| [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | Incorrect Authorization | `basic-splice`, `actor-client-mismatch`, `aud-sub-binding`, `upstream-splice`, `subject-actor-swap` |
| [CWE-269](https://cwe.mitre.org/data/definitions/269.html) | Improper Privilege Management | `scope-escalation`, `token-type-escalation`, `resource-abuse` |
| [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | Improper Access Control | `audience-targeting`, `may-act-enforcement` |

### Authentication

| CWE | Description | splice-check Vectors |
|-----|-------------|---------------------|
| [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | Improper Authentication | `unauthenticated-exchange`, `issuer-validation` |
| [CWE-613](https://cwe.mitre.org/data/definitions/613.html) | Insufficient Session Expiration | `expired-token-exchange`, `token-lifetime-reduction`, `refresh-bypass` |

### Data Integrity

| CWE | Description | splice-check Vectors |
|-----|-------------|---------------------|
| [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | Insufficient Verification of Data Authenticity | `delegation-impersonation-confusion`, `act-claim-stripping`, `act-sub-verification`, `act-nesting-integrity` |

### Availability

| CWE | Description | splice-check Vectors |
|-----|-------------|---------------------|
| [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Uncontrolled Resource Consumption | `chain-depth-exhaustion`, `circular-delegation` |

### Input Validation

| CWE | Description | splice-check Vectors |
|-----|-------------|---------------------|
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Improper Input Validation | `token-type-mismatch`, `missing-aud`, `multi-audience` |

---

## OWASP Mapping

| OWASP Top 10 (2021) | Relevant Vectors |
|---------------------|-----------------|
| A01: Broken Access Control | `basic-splice`, `actor-client-mismatch`, `aud-sub-binding`, `scope-escalation`, `audience-targeting`, `resource-abuse` |
| A02: Cryptographic Failures | `issuer-validation`, `expired-token-exchange` |
| A04: Insecure Design | `delegation-impersonation-confusion`, `act-claim-stripping`, `missing-aud`, `multi-audience` |
| A07: Identification and Authentication Failures | `unauthenticated-exchange`, `refresh-bypass` |
| A08: Software and Data Integrity Failures | `act-sub-verification`, `act-nesting-integrity`, `issued-token-type-validation` |

---

## Compliance Framework Mapping

### SOC 2

| Trust Service Criteria | Relevant Vectors | Control Objective |
|----------------------|------------------|--------------------|
| CC6.1 (Logical Access) | `basic-splice`, `actor-client-mismatch`, `unauthenticated-exchange` | Delegation requests are authenticated and authorized |
| CC6.3 (Access Revocation) | `revocation-propagation`, `refresh-bypass` | Token revocation propagates through delegation chains |
| CC6.6 (Scope Limitation) | `scope-escalation`, `token-type-escalation`, `resource-abuse` | Delegated tokens do not exceed source permissions |

### ISO 27001

| Control | Relevant Vectors |
|---------|-----------------|
| A.9.2.3 (Privileged Access Management) | `scope-escalation`, `token-type-escalation` |
| A.9.4.1 (Information Access Restriction) | `basic-splice`, `audience-targeting`, `resource-abuse` |
| A.12.4.1 (Event Logging) | `delegation-impersonation-confusion`, `act-sub-verification` |

---

## Remediation Priority Matrix

Based on severity and attack surface breadth:

### Priority 1: Critical Vulnerabilities (Immediate Action)

| Vector | Risk | Remediation |
|--------|------|-------------|
| `basic-splice` | Cross-chain delegation forgery | Implement cross-validation between subject and actor tokens |
| `actor-client-mismatch` | Actor impersonation | Bind authenticated client identity to actor_token.sub |
| `aud-sub-binding` | Token theft via audience bypass | Verify presenter identity matches subject_token.aud |
| `unauthenticated-exchange` | Unauthenticated token minting | Require client authentication on exchange endpoint |
| `issuer-validation` | Foreign token acceptance | Validate subject_token was issued by a trusted issuer |

### Priority 2: High Severity (1-2 Week Timeline)

| Vector | Risk | Remediation |
|--------|------|-------------|
| `act-claim-stripping` | Audit trail destruction | Preserve or reject delegation tokens during re-exchange |
| `delegation-impersonation-confusion` | Impersonation vs delegation confusion | Require `act` claim when `actor_token` is present |
| `downstream-aud-verification` | Unlimited token replay | Set constrained `aud` on delegated tokens |
| `scope-escalation` | Privilege escalation | Constrain delegated scope to subset of original |
| `revocation-propagation` | Revocation bypass | Propagate revocation through delegation chains |

### Priority 3: Medium Severity (30-Day Timeline)

| Vector | Risk | Remediation |
|--------|------|-------------|
| `token-lifetime-reduction` | Token persistence | Ensure delegated token exp ≤ original exp |
| `issued-token-type-validation` | Spec non-compliance | Include required `issued_token_type` in responses |
| `chain-depth-exhaustion` | DoS via token bloat | Enforce maximum delegation depth (3-5 recommended) |

---

## Report Template

Use this template for executive and compliance reporting:

### Token Exchange Security Assessment Report

**Date:** [Assessment Date]
**Target:** [AS Product/Version]
**Endpoint:** [Token Exchange URL]
**Assessor:** [Team/Individual]

**Summary:**

| Metric | Value |
|--------|-------|
| Total Vectors Tested | 28 |
| Passed | [N] |
| Failed (Vulnerabilities) | [N] |
| Skipped (Inconclusive) | [N] |
| Posture Score | [X]% |
| Rating | [Excellent/Good/Fair/Poor] |

**Critical Findings:**

[List any critical-severity failures with CWE mapping and remediation timeline]

**Recommendations:**

[Prioritized list based on severity and business impact]

**Evidence:**

```bash
# Command used
npx splice-check --config target.toml --format json > assessment-results.json

# Full report
npx splice-check --config target.toml --format markdown > assessment-report.md
```

---

## Vendor Evaluation Checklist

When evaluating Authorization Server products for token exchange support, use these questions:

1. Does the AS validate cross-chain authorization between subject and actor tokens?
2. Does the AS bind the authenticated client to the actor token identity?
3. Does the AS require client authentication for all token exchange requests?
4. Does the AS set constrained `aud` claims on delegated tokens?
5. Does the AS include `act` claims in delegation tokens?
6. Does the AS enforce delegation chain depth limits?
7. Does revocation of source tokens propagate to derived delegation tokens?
8. Does the AS validate `may_act` when present in subject tokens?

Vendors that answer "no" to questions 1-5 have critical delegation security gaps.

---

## Further Reading

- [What Is Chain Splicing?](what-is-chain-splicing.md) — Non-technical overview for stakeholders
- [Attack Vectors Reference](attack-vectors.md) — Full technical details
- [RFC 8693 Gap Analysis](rfc8693-gap-analysis.md) — Specification-level root cause analysis

---

*splice-check is part of the [oidc-loki](https://github.com/oidc-loki/oidc-loki) project. For authorized security testing only.*
