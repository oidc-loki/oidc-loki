/**
 * Test registry — exports all attack tests in execution order.
 *
 * Tests are ordered so that:
 *   1. Baseline (valid-delegation) runs first — if it fails, nothing else matters
 *   2. Core splice attacks run next
 *   3. Edge-case variants follow
 *   4. Operational tests (refresh, revocation) run last
 */

import { actClaimStripping } from "./act-claim-stripping.js";
import { actNestingIntegrity } from "./act-nesting-integrity.js";
import { actSubVerification } from "./act-sub-verification.js";
import { actorClientMismatch } from "./actor-client-mismatch.js";
import { audSubBinding } from "./aud-sub-binding.js";
import { audienceTargeting } from "./audience-targeting.js";
import { basicSplice } from "./basic-splice.js";
import { chainDepthExhaustion } from "./chain-depth-exhaustion.js";
import { circularDelegation } from "./circular-delegation.js";
import { delegationImpersonationConfusion } from "./delegation-impersonation-confusion.js";
import { downstreamAudVerification } from "./downstream-aud-verification.js";
import { expiredTokenExchange } from "./expired-token-exchange.js";
import { issuedTokenTypeValidation } from "./issued-token-type-validation.js";
import { issuerValidation } from "./issuer-validation.js";
import { mayActEnforcement } from "./may-act-enforcement.js";
import { missingAud } from "./missing-aud.js";
import { multiAudience } from "./multi-audience.js";
import { refreshBypass } from "./refresh-bypass.js";
import { resourceAbuse } from "./resource-abuse.js";
import { revocationPropagation } from "./revocation-propagation.js";
import { scopeEscalation } from "./scope-escalation.js";
import { subjectActorSwap } from "./subject-actor-swap.js";
import { tokenLifetimeReduction } from "./token-lifetime-reduction.js";
import { tokenTypeEscalation } from "./token-type-escalation.js";
import { tokenTypeMismatch } from "./token-type-mismatch.js";
import type { AttackTest } from "./types.js";
import { unauthenticatedExchange } from "./unauthenticated-exchange.js";
import { upstreamSplice } from "./upstream-splice.js";
import { validDelegation } from "./valid-delegation.js";

export const allTests: AttackTest[] = [
	// Baseline
	validDelegation,
	// Core splice attacks
	basicSplice,
	actorClientMismatch,
	audSubBinding,
	upstreamSplice,
	subjectActorSwap,
	// Input validation attacks
	tokenTypeMismatch,
	unauthenticatedExchange,
	tokenTypeEscalation,
	audienceTargeting,
	actClaimStripping,
	resourceAbuse,
	// Token forgery / validation attacks
	issuerValidation,
	expiredTokenExchange,
	// Edge-case variants
	multiAudience,
	missingAud,
	mayActEnforcement,
	scopeEscalation,
	delegationImpersonationConfusion,
	// Output validation tests
	issuedTokenTypeValidation,
	downstreamAudVerification,
	tokenLifetimeReduction,
	actSubVerification,
	actNestingIntegrity,
	// Delegation chain tests
	circularDelegation,
	chainDepthExhaustion,
	// Operational tests
	refreshBypass,
	revocationPropagation,
];

export function getTestById(id: string): AttackTest | undefined {
	return allTests.find((t) => t.id === id);
}

export function getTestIds(): string[] {
	return allTests.map((t) => t.id);
}

// Re-export types and utilities
export type { AttackTest, AttackResponse, SetupResult, TestContext, TestVerdict } from "./types.js";
export {
	classifyResponse,
	isSecurityRejection,
	isInconclusive,
	jsonBody,
	requireJsonBody,
	describeResponse,
} from "./classify.js";
export type { ResponseCategory } from "./classify.js";
