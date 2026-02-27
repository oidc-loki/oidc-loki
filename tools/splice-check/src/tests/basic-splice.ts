/**
 * Test 1: Basic Chain Splice
 *
 * The core attack: presents subject_token from Chain 1 (Alice → Agent A)
 * with actor_token from Chain 2 (Bob → Agent N). If the AS accepts this,
 * it produces a spliced token that falsely chains Alice's delegation
 * through an unrelated agent.
 */

import { describeResponse, isInconclusive, isSecurityRejection } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const basicSplice: AttackTest = {
	id: "basic-splice",
	name: "Basic Chain Splice",
	description:
		"Presents subject_token from Chain 1 with actor_token from Chain 2. " +
		"The AS should reject because actor_token.sub does not match subject_token.aud.",
	spec: "RFC 8693 Section 2.1",
	severity: "critical",

	async setup(ctx) {
		// Chain 1: Alice's token (obtained by Alice's client)
		ctx.log("Obtaining Alice's token (Chain 1 subject_token)");
		const aliceToken = await ctx.client.clientCredentials("alice");

		// Chain 2: Agent N's own credential (separate chain)
		ctx.log("Obtaining Agent N's token (Chain 2 actor_token)");
		const agentNToken = await ctx.client.clientCredentials("agent-n");

		return {
			tokens: {
				subjectToken: aliceToken,
				actorToken: agentNToken,
			},
		};
	},

	async attack(ctx, setup) {
		ctx.log("Attempting cross-chain exchange: Alice's token + Agent N's token");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: requireToken(setup, "actorToken"),
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-n",
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS rejected cross-chain splice — ${describeResponse(response)}`,
			};
		}
		if (isInconclusive(response)) {
			return {
				skipped: true,
				reason: `Inconclusive: ${describeResponse(response)} (not a security rejection)`,
			};
		}
		return {
			passed: false,
			reason: "AS accepted spliced token pair from different delegation chains",
			expected: "Security rejection (invalid_grant or invalid_request)",
			actual: `${describeResponse(response)} — spliced token issued`,
		};
	},
};
