/**
 * Test 10: Delegation vs Impersonation Confusion (DI-01)
 *
 * RFC 8693 Section 1.1 distinguishes delegation (actor_token present,
 * resulting token has `act` claim) from impersonation (no actor_token,
 * resulting token has same `sub`).
 *
 * This test verifies that when delegation is explicitly requested
 * (actor_token provided), the AS issues a proper delegation token
 * with an `act` claim — not an impersonation token.
 */

import { decodeJwt } from "jose";
import { describeResponse, isInconclusive, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const delegationImpersonationConfusion: AttackTest = {
	id: "delegation-impersonation-confusion",
	name: "Delegation vs Impersonation Confusion",
	description:
		"Performs an exchange with actor_token and verifies the resulting token contains " +
		"an `act` claim (delegation). Without `act`, the token is an impersonation token, " +
		"which loses the delegation audit trail.",
	spec: "RFC 8693 Section 1.1 + Section 4.1",
	severity: "high",

	async setup(ctx) {
		ctx.log("Obtaining Alice's token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		ctx.log("Obtaining Agent A's token");
		const agentAToken = await ctx.client.clientCredentials("agent-a");

		return {
			tokens: {
				subjectToken: aliceToken,
				actorToken: agentAToken,
			},
		};
	},

	async attack(ctx, setup) {
		ctx.log("Performing delegation exchange (with actor_token — expecting act claim in result)");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: requireToken(setup, "actorToken"),
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
		});
	},

	verify(response) {
		if (response.status !== 200) {
			if (isInconclusive(response)) {
				return {
					skipped: true,
					reason: `Inconclusive: ${describeResponse(response)}`,
				};
			}
			return {
				skipped: true,
				reason: `Exchange was rejected — ${describeResponse(response)}. Cannot verify act claim.`,
			};
		}

		const body = jsonBody(response);
		const accessToken = body?.access_token as string | undefined;
		if (!accessToken) {
			return {
				passed: false,
				reason: "Exchange succeeded but response has no access_token",
				expected: "access_token with act claim",
				actual: `HTTP 200 with keys: ${body ? Object.keys(body).join(", ") : "none"}`,
			};
		}

		// Try to decode the JWT and check for `act` claim
		try {
			const claims = decodeJwt(accessToken);
			if (claims.act !== undefined) {
				return {
					passed: true,
					reason: "Delegated token contains `act` claim — proper delegation semantics",
				};
			}
			return {
				passed: false,
				reason:
					"Delegated token does NOT contain `act` claim — AS issued impersonation token " +
					"instead of delegation token, losing the delegation audit trail",
				expected: "JWT with `act` claim (RFC 8693 Section 4.1)",
				actual: `JWT claims: ${Object.keys(claims).join(", ")} (no act)`,
			};
		} catch {
			// Token is opaque (not a JWT) — can't verify act claim
			return {
				skipped: true,
				reason:
					"Resulting token is opaque (not a JWT) — cannot verify `act` claim. " +
					"This test requires the AS to issue JWT access tokens.",
			};
		}
	},
};
