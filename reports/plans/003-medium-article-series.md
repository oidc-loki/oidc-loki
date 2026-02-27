# Plan 003: Medium Article Series

**Status:** Part 1 ready for publication
**Priority:** P0
**Depends on:** None (Part 1). Plan 001 (Parts 2-3).

---

## Series Structure

### Part 1: "The Trust Gap in Agentic Delegation" (READY)

- Thought piece framing the gap between industry zero-trust vision and spec coverage
- Red Hat article as hook
- Describes the gap conceptually without exploit details
- Actionable checklist for implementers
- Files: `publications/medium-part1-final.html`, `publications/medium-part1-draft.md`
- Diagrams: `publications/diagram1.png`, `publications/diagram2.png`

### Part 2: "Closing the Gap: A Mitigation Profile for Delegated Token Exchange" (DRAFT LATER)

- The 7 edge cases in detail (without step-by-step exploit)
- The 8-point mitigation profile (6 original + issuer federation + threat signaling)
- Framed as defensive guidance
- References IETF engagement and Ayesha's work
- Timing: After Part 1 gets traction and Ayesha's reply comes in

### Part 3: "Testing Your Authorization Server for Delegation Attacks" (AFTER PLAN 001)

- Introduces splice-check CLI
- Test methodology and what each test checks
- How to run against WSO2, Keycloak
- Links to the GitHub repo
- Timing: After Plan 001 ships

## Publication Checklist

- [x] Part 1 drafted
- [x] Part 1 reviewed by Gemini (2 rounds)
- [x] Diagrams generated (PNG, Medium-compatible)
- [x] Disclosure framing vetted ("raised this gap" not "disclosed vulnerability")
- [x] Legal/professional risk assessed (minimal)
- [ ] Publish Part 1 on Medium
- [ ] Share link on IETF oauth list as follow-up to existing thread
- [ ] Draft Part 2 after Ayesha's reply
- [ ] Draft Part 3 after Plan 001 delivers working CLI
