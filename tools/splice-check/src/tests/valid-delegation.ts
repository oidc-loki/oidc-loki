/**
 * Test 0: Valid Delegation (baseline)
 *
 * Verifies that the AS correctly processes a legitimate token exchange
 * where the delegation chain is intact. This must pass for the remaining
 * tests to be meaningful.
 */

import { describeResponse, isInconclusive, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const validDelegation: AttackTest = {
	id: "valid-delegation",
	name: "Valid Delegation (baseline)",
	description:
		"Performs a legitimate token exchange: Alice's token exchanged by Agent A. " +
		"This baseline must succeed for other tests to be meaningful.",
	spec: "RFC 8693 Section 2.1",
	severity: "critical",

	async setup(ctx) {
		ctx.log("Obtaining Alice's token via client_credentials");
		const aliceToken = await ctx.client.clientCredentials("alice");

		return {
			tokens: { aliceToken },
		};
	},

	async attack(ctx, setup) {
		ctx.log("Exchanging Alice's token via Agent A (legitimate delegation)");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "aliceToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
		});
	},

	verify(response) {
		if (response.status === 200) {
			const body = jsonBody(response);
			if (body?.access_token) {
				return { passed: true, reason: "AS accepted valid delegation" };
			}
			return {
				passed: false,
				reason: "AS returned 200 but no access_token in response body",
				expected: "200 with access_token",
				actual: `200 with body: ${String(response.body).slice(0, 100)}`,
			};
		}
		if (isInconclusive(response)) {
			return {
				skipped: true,
				reason: `Baseline inconclusive: ${describeResponse(response)}. Check client configuration.`,
			};
		}
		return {
			passed: false,
			reason: "AS rejected valid delegation",
			expected: "HTTP 200 with access_token",
			actual: describeResponse(response),
		};
	},
};
