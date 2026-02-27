/**
 * Test 9: Actor-Client Mismatch (ACT-01)
 *
 * The most direct form of actor impersonation: Agent N authenticates with
 * its own client_id/client_secret, but presents an actor_token whose `sub`
 * is Agent A. The AS MUST verify that the authenticated client matches the
 * actor_token.sub claim. If it doesn't, this is a Critical vulnerability.
 */

import { describeResponse, isInconclusive, isSecurityRejection } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const actorClientMismatch: AttackTest = {
	id: "actor-client-mismatch",
	name: "Actor-Client Identity Mismatch",
	description:
		"Agent N authenticates as itself but presents Agent A's token as actor_token. " +
		"The AS must verify that the authenticated client matches the actor_token.sub.",
	spec: "RFC 8693 Section 2.1 (act claim binding)",
	severity: "critical",

	async setup(ctx) {
		// Get Alice's token as subject
		ctx.log("Obtaining Alice's token (subject)");
		const aliceToken = await ctx.client.clientCredentials("alice");

		// Get Agent A's token — this will be presented as actor_token,
		// but Agent N (different client) will authenticate
		ctx.log("Obtaining Agent A's token (to use as mismatched actor_token)");
		const agentAToken = await ctx.client.clientCredentials("agent-a");

		return {
			tokens: {
				subjectToken: aliceToken,
				actorToken: agentAToken, // sub=agent-a
			},
		};
	},

	async attack(ctx, setup) {
		// Agent N authenticates (clientName: "agent-n") but presents
		// Agent A's token as actor_token (sub mismatch with authenticated client)
		ctx.log("Agent N authenticating but presenting Agent A's token as actor_token");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: requireToken(setup, "actorToken"),
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-n", // Authenticated as agent-n, but actor_token.sub = agent-a
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS verified actor_token.sub matches authenticated client — ${describeResponse(response)}`,
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
			reason:
				"AS did not verify that actor_token.sub matches the authenticated client — " +
				"actor impersonation possible",
			expected: "Security rejection (actor_token.sub ≠ authenticated client_id)",
			actual: `${describeResponse(response)} — token issued despite actor identity mismatch`,
		};
	},
};
