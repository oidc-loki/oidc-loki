/**
 * Test 5: Missing Audience Claim
 *
 * When a subject_token has no `aud` claim at all, the aud/sub binding
 * cannot be validated. The AS should either reject the token outright
 * or apply additional validation (e.g., may_act, delegation policy).
 * Accepting a token without aud in a delegation exchange is dangerous.
 */

import { decodeJwt } from "jose";
import { describeResponse, isInconclusive, isSecurityRejection } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const missingAud: AttackTest = {
	id: "missing-aud",
	name: "Missing Audience Claim",
	description:
		"Attempts exchange with a subject_token that lacks an aud claim. " +
		"Without aud, the AS cannot perform aud/sub binding validation.",
	spec: "RFC 8693 Section 2.1 + RFC 7519 Section 4.1.3",
	severity: "high",

	async setup(ctx) {
		ctx.log("Obtaining Alice's token to check for aud claim");
		const aliceToken = await ctx.client.clientCredentials("alice");

		let hasAud = true;
		try {
			const claims = decodeJwt(aliceToken);
			hasAud = claims.aud !== undefined;
			ctx.log(`Alice's token has aud: ${hasAud} (value: ${JSON.stringify(claims.aud)})`);
		} catch {
			ctx.log("Could not decode Alice's token (may be opaque) — test may be inconclusive");
		}

		const agentNToken = await ctx.client.clientCredentials("agent-n");

		return {
			tokens: {
				subjectToken: aliceToken,
				actorToken: agentNToken,
			},
			metadata: { hasAud },
		};
	},

	async attack(ctx, setup) {
		ctx.log("Attempting exchange with subject_token (checking aud handling)");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: requireToken(setup, "actorToken"),
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-n",
		});
	},

	verify(response, setup) {
		const hasAud = setup.metadata?.hasAud as boolean | undefined;

		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS rejected exchange — ${describeResponse(response)}${hasAud === false ? " (correctly rejected token without aud)" : ""}`,
			};
		}

		if (isInconclusive(response)) {
			return {
				skipped: true,
				reason: `Inconclusive: ${describeResponse(response)} (not a security rejection)`,
			};
		}

		if (hasAud === false) {
			return {
				passed: false,
				reason: "AS accepted exchange with subject_token missing aud claim",
				expected: "Security rejection (no aud to validate against)",
				actual: `${describeResponse(response)} — token issued without aud/sub binding`,
			};
		}

		return {
			passed: false,
			reason: "AS accepted cross-chain exchange despite aud presence",
			expected: "Security rejection",
			actual: `${describeResponse(response)} — token issued`,
		};
	},
};
