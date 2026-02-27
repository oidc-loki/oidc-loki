/**
 * Test 4: Multi-Audience Subject Token
 *
 * When a subject_token has a multi-valued `aud` claim (an array), the
 * aud/sub binding check becomes ambiguous — which audience should match
 * the actor? An AS that only checks "is actor.sub IN subject.aud" (rather
 * than exact match) may be vulnerable to splice attacks where the attacker's
 * identity is one of many audiences.
 */

import { decodeJwt } from "jose";
import { describeResponse, isInconclusive, isSecurityRejection } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const multiAudience: AttackTest = {
	id: "multi-audience",
	name: "Multi-Audience Subject Token",
	description:
		"Tests whether the AS properly handles subject_tokens with multi-valued aud arrays. " +
		"A permissive 'is actor IN aud' check can enable splice attacks.",
	spec: "RFC 8693 Section 2.1 + RFC 7519 Section 4.1.3",
	severity: "high",

	async setup(ctx) {
		// Get Alice's token — check if it has multi-valued aud
		ctx.log("Obtaining Alice's token to inspect aud claim");
		const aliceToken = await ctx.client.clientCredentials("alice");

		let hasMultiAud = false;
		try {
			const claims = decodeJwt(aliceToken);
			hasMultiAud = Array.isArray(claims.aud) && claims.aud.length > 1;
			ctx.log(`Alice's token aud: ${JSON.stringify(claims.aud)} (multi-valued: ${hasMultiAud})`);
		} catch {
			ctx.log("Could not decode Alice's token (may be opaque)");
		}

		// Get Agent N's token
		const agentNToken = await ctx.client.clientCredentials("agent-n");

		return {
			tokens: {
				subjectToken: aliceToken,
				actorToken: agentNToken,
			},
			metadata: { hasMultiAud },
		};
	},

	async attack(ctx, setup) {
		ctx.log("Attempting exchange with potentially multi-audience subject_token");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: requireToken(setup, "actorToken"),
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-n",
		});
	},

	verify(response, setup) {
		const hasMultiAud = setup.metadata?.hasMultiAud as boolean | undefined;

		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS rejected exchange with${hasMultiAud ? " multi-audience" : ""} subject_token — ${describeResponse(response)}`,
			};
		}

		if (isInconclusive(response)) {
			return {
				skipped: true,
				reason: `Inconclusive: ${describeResponse(response)} (not a security rejection)`,
			};
		}

		if (!hasMultiAud) {
			return {
				passed: false,
				reason: "AS accepted cross-chain exchange (subject_token did not have multi-valued aud)",
				expected: "Security rejection",
				actual: `${describeResponse(response)} — token issued`,
			};
		}

		return {
			passed: false,
			reason: "AS accepted exchange with multi-audience subject_token — permissive aud matching",
			expected: "Security rejection (strict aud/sub binding despite multi-valued aud)",
			actual: `${describeResponse(response)} — token issued, multi-aud bypass possible`,
		};
	},
};
