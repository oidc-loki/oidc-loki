/**
 * Test 6: may_act Enforcement
 *
 * RFC 8693 Section 4.4 defines the `may_act` claim which explicitly
 * lists actors authorized to act on behalf of the subject. If the AS
 * supports may_act, it MUST reject exchanges where the actor is not
 * listed. If the AS does not support may_act, this test is skipped.
 */

import { decodeJwt } from "jose";
import { describeResponse, isInconclusive, isSecurityRejection } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const mayActEnforcement: AttackTest = {
	id: "may-act-enforcement",
	name: "may_act Enforcement",
	description:
		"Verifies that the AS enforces the may_act claim by rejecting " +
		"exchanges from actors not listed in the subject_token's may_act.",
	spec: "RFC 8693 Section 4.4",
	severity: "high",

	async setup(ctx) {
		ctx.log("Obtaining Alice's token to check for may_act claim");
		const aliceToken = await ctx.client.clientCredentials("alice");

		let hasMayAct = false;
		try {
			const claims = decodeJwt(aliceToken);
			const mayAct = claims.may_act as Record<string, unknown> | undefined;
			hasMayAct = mayAct !== undefined;
			ctx.log(`Alice's token has may_act: ${hasMayAct}`);
			if (hasMayAct) {
				ctx.log(`may_act value: ${JSON.stringify(mayAct)}`);
			}
		} catch {
			ctx.log("Could not decode Alice's token — may_act check skipped");
		}

		const agentNToken = await ctx.client.clientCredentials("agent-n");

		return {
			tokens: {
				subjectToken: aliceToken,
				actorToken: agentNToken,
			},
			metadata: { hasMayAct },
		};
	},

	async attack(ctx, setup) {
		ctx.log("Attempting exchange with unauthorized actor (Agent N not in may_act)");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: requireToken(setup, "actorToken"),
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-n",
		});
	},

	verify(response, setup) {
		const hasMayAct = setup.metadata?.hasMayAct as boolean | undefined;

		if (!hasMayAct) {
			if (isSecurityRejection(response)) {
				return {
					passed: true,
					reason: `AS rejected exchange (may_act not present, but AS still validated) — ${describeResponse(response)}`,
				};
			}
			if (isInconclusive(response)) {
				return {
					skipped: true,
					reason: `Inconclusive: ${describeResponse(response)}`,
				};
			}
			return {
				skipped: true,
				reason:
					"Subject token does not contain may_act claim — " +
					"AS may not support RFC 8693 Section 4.4 delegation authorization",
			};
		}

		// may_act is present — AS must enforce it
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS enforced may_act — rejected unauthorized actor — ${describeResponse(response)}`,
			};
		}

		if (isInconclusive(response)) {
			return {
				skipped: true,
				reason: `Inconclusive: ${describeResponse(response)}`,
			};
		}

		return {
			passed: false,
			reason: "AS ignored may_act claim — accepted exchange from unauthorized actor",
			expected: "Security rejection (Agent N not in may_act)",
			actual: `${describeResponse(response)} — token issued despite may_act violation`,
		};
	},
};
