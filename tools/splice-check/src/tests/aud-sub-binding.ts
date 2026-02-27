/**
 * Test 2: Audience-Subject Binding Check
 *
 * Verifies that the AS validates subject_token.aud matches actor_token.sub.
 * This is the fundamental cross-validation that prevents chain splicing.
 * We request an exchange where the subject_token is scoped to Agent A's
 * audience, but Agent N (different sub) presents it.
 */

import { describeResponse, isInconclusive, isSecurityRejection } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const audSubBinding: AttackTest = {
	id: "aud-sub-binding",
	name: "Audience-Subject Binding",
	description:
		"Exchanges a subject_token whose aud targets Agent A, but Agent N presents it. " +
		"The AS must verify that the presenting actor's identity matches the token's intended audience.",
	spec: "RFC 8693 Section 2.1 + Section 4.1",
	severity: "critical",

	async setup(ctx) {
		// Get Alice's token (will have aud for Alice's client or the AS)
		ctx.log("Obtaining Alice's token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		// Exchange to get a token scoped to Agent A's audience
		const agentAClientId = ctx.config.clients["agent-a"]?.client_id;
		if (!agentAClientId) {
			throw new Error("Setup: agent-a client not configured");
		}

		ctx.log("Exchanging Alice's token with audience=agent-a");
		const chain1Response = await ctx.client.tokenExchange({
			subject_token: aliceToken,
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			audience: agentAClientId,
			clientName: "agent-a",
		});

		if (chain1Response.status !== 200) {
			throw new Error(
				`Setup: could not obtain audience-scoped token (HTTP ${chain1Response.status}). Ensure the AS supports audience-restricted token exchange.`,
			);
		}

		const chain1Body = chain1Response.body as Record<string, unknown>;
		const scopedToken = chain1Body.access_token as string;

		// Get Agent N's own token
		ctx.log("Obtaining Agent N's token");
		const agentNToken = await ctx.client.clientCredentials("agent-n");

		return {
			tokens: {
				subjectToken: scopedToken, // aud=agent-a
				actorToken: agentNToken, // sub=agent-n (mismatch!)
			},
		};
	},

	async attack(ctx, setup) {
		ctx.log("Attempting exchange with aud/sub mismatch (aud=agent-a, actor=agent-n)");
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
				reason: `AS validated aud/sub binding — ${describeResponse(response)}`,
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
			reason: "AS did not validate that actor_token.sub matches subject_token.aud",
			expected: "Security rejection (aud/sub mismatch)",
			actual: `${describeResponse(response)} — token issued despite aud/sub mismatch`,
		};
	},
};
