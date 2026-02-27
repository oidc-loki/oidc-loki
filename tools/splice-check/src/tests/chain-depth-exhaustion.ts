/**
 * TE-09: Delegation Chain Depth Exhaustion
 *
 * RFC 8693 Section 4.1: Each delegation hop adds a nested `act` layer to the
 * JWT. Without a maximum depth policy, iterative chaining creates token bloat,
 * potential parser crashes, and DoS vectors.
 *
 * This test performs successive delegation exchanges to see if the AS enforces
 * a maximum chain depth.
 */

import { describeResponse, isInconclusive, isSecurityRejection, jsonBody } from "./classify.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

const MAX_DEPTH_TO_TEST = 5;

export const chainDepthExhaustion: AttackTest = {
	id: "chain-depth-exhaustion",
	name: "Delegation Chain Depth Exhaustion",
	description: `Performs ${MAX_DEPTH_TO_TEST} successive delegation exchanges to test whether the AS enforces a maximum chain depth. Unbounded chains cause token bloat and DoS.`,
	spec: "RFC 8693 Section 4.1",
	severity: "high",

	async setup(ctx) {
		ctx.log("Obtaining initial tokens");
		const aliceToken = await ctx.client.clientCredentials("alice");

		// Perform successive exchanges, alternating between agent-a and agent-n
		let currentToken = aliceToken;
		let depth = 0;

		for (let i = 0; i < MAX_DEPTH_TO_TEST - 1; i++) {
			const agent = i % 2 === 0 ? "agent-a" : "agent-n";
			ctx.log(`Delegation hop ${i + 1}: → ${agent}`);

			const actorToken = await ctx.client.clientCredentials(agent);
			const response = await ctx.client.tokenExchange({
				subject_token: currentToken,
				subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
				actor_token: actorToken,
				actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
				clientName: agent,
			});

			if (response.status !== 200) {
				// AS rejected at this depth — that's the enforcement point
				ctx.log(`AS rejected at depth ${i + 1}: HTTP ${response.status}`);
				return {
					tokens: {},
					metadata: { rejectedAtDepth: i + 1, depthReached: depth },
				};
			}

			const body = jsonBody(response);
			const token = body?.access_token as string | undefined;
			if (!token) {
				throw new Error(`Setup: hop ${i + 1} returned 200 but no access_token`);
			}

			currentToken = token;
			depth = i + 1;
		}

		ctx.log(`Reached depth ${depth} without rejection`);
		return {
			tokens: { deepToken: currentToken },
			metadata: { depthReached: depth },
		};
	},

	async attack(ctx, setup) {
		const rejectedAtDepth = setup.metadata?.rejectedAtDepth as number | undefined;
		if (rejectedAtDepth !== undefined) {
			// AS already rejected during setup — return a synthetic response
			ctx.log(`AS already rejected at depth ${rejectedAtDepth} during setup`);
			return { status: 400, body: { error: "chain_depth_exceeded" }, headers: {}, durationMs: 0 };
		}

		// Try one more exchange to push past the depth
		const depthReached = setup.metadata?.depthReached as number;
		const agent = depthReached % 2 === 0 ? "agent-a" : "agent-n";
		ctx.log(`Attempting delegation hop ${depthReached + 1}: → ${agent} (testing depth limit)`);

		const actorToken = await ctx.client.clientCredentials(agent);
		return ctx.client.tokenExchange({
			subject_token: setup.tokens.deepToken ?? "",
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: actorToken,
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: agent,
		});
	},

	verify(response, setup) {
		const rejectedAtDepth = setup.metadata?.rejectedAtDepth as number | undefined;

		// If AS rejected during setup, chain depth is enforced
		if (rejectedAtDepth !== undefined) {
			return {
				passed: true,
				reason: `AS enforced chain depth limit — rejected at depth ${rejectedAtDepth}`,
			};
		}

		if (isSecurityRejection(response)) {
			const depthReached = setup.metadata?.depthReached as number;
			return {
				passed: true,
				reason: `AS enforced chain depth limit at depth ${depthReached + 1} — ${describeResponse(response)}`,
			};
		}

		if (isInconclusive(response)) {
			return {
				skipped: true,
				reason: `Inconclusive: ${describeResponse(response)}`,
			};
		}

		if (response.status === 200) {
			const depthReached = setup.metadata?.depthReached as number;
			return {
				passed: false,
				reason: `AS accepted ${depthReached + 1} delegation hops with no depth limit — unbounded chain growth possible (token bloat, DoS vector)`,
				expected: "Rejection at some maximum chain depth",
				actual: `${describeResponse(response)} — depth ${depthReached + 1} accepted`,
			};
		}

		return {
			passed: false,
			reason: "Unexpected response to deep delegation chain",
			expected: "Rejection or depth limit enforcement",
			actual: describeResponse(response),
		};
	},
};
