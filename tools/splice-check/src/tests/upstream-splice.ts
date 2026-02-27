/**
 * Test 3: Upstream Delegation Splice
 *
 * An attacker (Agent N) obtains a delegated token from one chain and
 * attempts to re-delegate it to an unauthorized downstream agent.
 * The AS should reject because the delegation context doesn't authorize
 * this re-delegation path.
 */

import { describeResponse, isInconclusive, isSecurityRejection } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const upstreamSplice: AttackTest = {
	id: "upstream-splice",
	name: "Upstream Delegation Splice",
	description:
		"Agent A obtains a legitimate delegated token, then Agent N attempts to " +
		"re-delegate it to itself. The AS should reject unauthorized re-delegation.",
	spec: "RFC 8693 Section 2.1 + Section 4.4 (may_act)",
	severity: "high",

	async setup(ctx) {
		// Get Alice's token
		ctx.log("Obtaining Alice's token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		// Legitimate exchange: Alice → Agent A
		ctx.log("Performing legitimate exchange: Alice → Agent A");
		const chain1Response = await ctx.client.tokenExchange({
			subject_token: aliceToken,
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
		});

		if (chain1Response.status !== 200) {
			throw new Error(`Setup: legitimate exchange failed (HTTP ${chain1Response.status})`);
		}

		const chain1Body = chain1Response.body as Record<string, unknown>;
		const delegatedToken = chain1Body.access_token as string;

		// Get Agent N's own token
		ctx.log("Obtaining Agent N's token");
		const agentNToken = await ctx.client.clientCredentials("agent-n");

		return {
			tokens: {
				delegatedToken, // Alice → Agent A delegation
				agentNToken, // Agent N's own credential
			},
		};
	},

	async attack(ctx, setup) {
		ctx.log("Agent N attempting to re-delegate Agent A's token to itself");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "delegatedToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: requireToken(setup, "agentNToken"),
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-n",
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS rejected unauthorized re-delegation — ${describeResponse(response)}`,
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
			reason: "AS allowed re-delegation to unauthorized agent",
			expected: "Security rejection (unauthorized re-delegation)",
			actual: `${describeResponse(response)} — re-delegated token issued to Agent N`,
		};
	},
};
