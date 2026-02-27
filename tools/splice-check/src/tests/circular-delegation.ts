/**
 * TE-08: Circular Delegation Chain
 *
 * RFC 8693 Section 4.1: Delegation chains are expressed via nested `act` claims.
 * If Agent A delegates to Agent N, which then re-delegates back to Agent A,
 * a circular chain is created (A → N → A). Without cycle detection, this can
 * cause infinite validator loops, unbounded chain growth, or confused
 * authorization decisions.
 */

import { describeResponse, isInconclusive, isSecurityRejection, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const circularDelegation: AttackTest = {
	id: "circular-delegation",
	name: "Circular Delegation Chain",
	description:
		"Creates a delegation chain A→N, then attempts to re-delegate back to A, " +
		"forming a circular chain. The AS should reject circular delegation.",
	spec: "RFC 8693 Section 4.1",
	severity: "high",

	async setup(ctx) {
		// Step 1: Get Alice's token
		ctx.log("Obtaining Alice's token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		// Step 2: Delegate Alice → Agent A
		ctx.log("Performing delegation: Alice → Agent A");
		const agentAToken = await ctx.client.clientCredentials("agent-a");
		const hop1Response = await ctx.client.tokenExchange({
			subject_token: aliceToken,
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: agentAToken,
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
		});

		if (hop1Response.status !== 200) {
			throw new Error(`Setup: first delegation failed (HTTP ${hop1Response.status})`);
		}

		const hop1Body = jsonBody(hop1Response);
		const hop1Token = hop1Body?.access_token as string | undefined;
		if (!hop1Token) {
			throw new Error("Setup: first delegation returned no access_token");
		}

		// Step 3: Delegate hop1 → Agent N
		ctx.log("Performing delegation: Agent A → Agent N");
		const agentNToken = await ctx.client.clientCredentials("agent-n");
		const hop2Response = await ctx.client.tokenExchange({
			subject_token: hop1Token,
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: agentNToken,
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-n",
		});

		if (hop2Response.status !== 200) {
			throw new Error(`Setup: second delegation failed (HTTP ${hop2Response.status})`);
		}

		const hop2Body = jsonBody(hop2Response);
		const hop2Token = hop2Body?.access_token as string | undefined;
		if (!hop2Token) {
			throw new Error("Setup: second delegation returned no access_token");
		}

		return {
			tokens: { hop2Token, agentAToken },
		};
	},

	async attack(ctx, setup) {
		// Step 4: Try to delegate hop2 back to Agent A (circular!)
		ctx.log("Attempting circular delegation: Agent N → Agent A (creating A→N→A cycle)");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "hop2Token"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: requireToken(setup, "agentAToken"),
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS detected and rejected circular delegation — ${describeResponse(response)}`,
			};
		}

		if (isInconclusive(response)) {
			return {
				skipped: true,
				reason: `Inconclusive: ${describeResponse(response)}`,
			};
		}

		if (response.status === 200) {
			const body = jsonBody(response);
			if (body?.access_token) {
				return {
					passed: false,
					reason:
						"AS accepted circular delegation chain (A→N→A) — " +
						"no cycle detection in delegation chain",
					expected: "Rejection of circular delegation",
					actual: `${describeResponse(response)} — circular chain token issued`,
				};
			}
		}

		return {
			passed: false,
			reason: "Unexpected response to circular delegation attempt",
			expected: "Rejection of circular delegation",
			actual: describeResponse(response),
		};
	},
};
