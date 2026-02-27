# Plan 004: IETF Spec Contribution

**Status:** In progress (engaged with OBO draft co-author)
**Priority:** P0
**Depends on:** Plan 001 (for test vectors)

---

## Goal

Contribute chain-splicing mitigation language to the OAuth working group, targeting inclusion in draft-oauth-ai-agents-on-behalf-of-user or a standalone security profile.

## Current Status

- Chain splicing disclosed to oauth@ietf.org
- Ayesha Dissanayaka (WSO2, OBO draft co-author) engaged and validating
- Reply drafted with 7 edge cases and 6-point mitigation profile
- Awaiting Ayesha's response to technical reply
- Files: `correspondence/reply-to-ayesha-draft.md`

## The Mitigation Profile (8 points)

1. AS MUST verify `subject_token.aud` matches `actor_token.sub` at each exchange
2. For delegation chains, `subject_token` MUST carry single-valued `aud`
3. AS MUST validate delegation against policy (`may_act` or equivalent)
4. AS SHOULD issue new token with `aud` set to intended downstream actor
5. Short token lifetimes + back-channel revocation
6. Refresh tokens from delegated exchange MUST re-validate delegation context
7. AS MUST validate issuer federation context in cross-domain scenarios (Gemini addition)
8. Failed splice validation MUST be logged as high-severity security event (Gemini addition)

## Deliverables

- [ ] Spec-ready language (MUST/SHOULD/MAY per RFC 2119) for the mitigation profile
- [ ] Test vectors (from Plan 001) that the spec can reference
- [ ] Formal response to Ayesha with proposed draft text
- [ ] If appropriate: standalone Internet-Draft for "Security Profile for Delegated Token Exchange"

## Open Questions

- Does this belong in the OBO draft or as a standalone profile?
- Should we propose a new `delegation_context` claim for binding tokens to the same flow?
- How to handle the multi-instance actor resolution (service principal to instance mapping)?
