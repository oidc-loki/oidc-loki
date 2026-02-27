/**
 * Test 12: Subject-Actor Token Swap
 *
 * The attacker swaps the subject_token and actor_token: presenting
 * Alice's token as the actor_token and Agent N's token as the subject_token.
 * This inverts the delegation relationship and should be rejected.
 */

import { describeResponse, isInconclusive, isSecurityRejection } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const subjectActorSwap: AttackTest = {
	id: "subject-actor-swap",
	name: "Subject-Actor Token Swap",
	description:
		"Swaps subject_token and actor_token: presents the attacker's token as subject " +
		"and the victim's token as actor. This inverts the delegation relationship.",
	spec: "RFC 8693 Section 2.1",
	severity: "high",

	async setup(ctx) {
		ctx.log("Obtaining Alice's token (victim — will be misused as actor_token)");
		const aliceToken = await ctx.client.clientCredentials("alice");

		ctx.log("Obtaining Agent N's token (attacker — will be misused as subject_token)");
		const agentNToken = await ctx.client.clientCredentials("agent-n");

		return {
			tokens: {
				aliceToken,
				agentNToken,
			},
		};
	},

	async attack(ctx, setup) {
		// Swap: Agent N's token as subject, Alice's as actor
		ctx.log("Attempting exchange with swapped subject/actor tokens");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "agentNToken"), // Attacker as subject
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: requireToken(setup, "aliceToken"), // Victim as actor (inverted!)
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-n",
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS rejected swapped subject/actor tokens — ${describeResponse(response)}`,
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
			reason:
				"AS accepted exchange with swapped subject/actor tokens — " +
				"delegation relationship can be inverted",
			expected: "Security rejection (subject/actor role inversion)",
			actual: `${describeResponse(response)} — inverted delegation token issued`,
		};
	},
};
