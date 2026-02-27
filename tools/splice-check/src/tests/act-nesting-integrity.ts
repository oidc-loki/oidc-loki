/**
 * TE-16: `act` Claim Nesting Integrity
 *
 * RFC 8693 Section 4.1: "A chain of delegation can be expressed by nesting
 * one act claim within another." After multi-hop delegation (Alice → Agent A →
 * Agent N), the resulting token's `act` chain should correctly reflect the
 * delegation history. Non-identity claims (exp, nbf, aud) should NOT appear
 * inside `act` objects.
 */

import { decodeJwt } from "jose";
import { describeResponse, isInconclusive, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

const NON_IDENTITY_CLAIMS = new Set(["exp", "nbf", "iat", "aud", "iss", "jti", "scope"]);

export const actNestingIntegrity: AttackTest = {
	id: "act-nesting-integrity",
	name: "act Claim Nesting Integrity",
	description:
		"Performs a multi-hop delegation and verifies the resulting token's `act` chain " +
		"correctly reflects the delegation history with no non-identity claim leakage.",
	spec: "RFC 8693 Section 4.1",
	severity: "high",

	async setup(ctx) {
		// Step 1: Get Alice's token
		ctx.log("Obtaining Alice's token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		// Step 2: Exchange Alice → Agent A (first hop)
		ctx.log("Performing first delegation: Alice → Agent A");
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

		return {
			tokens: { hop1Token },
		};
	},

	async attack(ctx, setup) {
		// Step 3: Exchange hop1Token → Agent N (second hop)
		ctx.log("Performing second delegation: hop1 → Agent N (multi-hop chain)");
		const agentNToken = await ctx.client.clientCredentials("agent-n");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "hop1Token"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: agentNToken,
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-n",
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
				reason: `Second hop rejected — ${describeResponse(response)}. Cannot verify nesting.`,
			};
		}

		const body = jsonBody(response);
		const accessToken = body?.access_token as string | undefined;
		if (!accessToken) {
			return {
				passed: false,
				reason: "Exchange returned 200 but no access_token",
				expected: "access_token with nested act claims",
				actual: describeResponse(response),
			};
		}

		try {
			const claims = decodeJwt(accessToken);
			const act = claims.act as Record<string, unknown> | undefined;

			if (!act) {
				return {
					passed: false,
					reason: "Multi-hop delegation token has no act claim — delegation chain lost",
					expected: "Nested act claims reflecting delegation history",
					actual: `JWT claims: ${Object.keys(claims).join(", ")} (no act)`,
				};
			}

			// Check for non-identity claims leaked into act
			const leakedClaims = Object.keys(act).filter((k) => NON_IDENTITY_CLAIMS.has(k));
			if (leakedClaims.length > 0) {
				return {
					passed: false,
					reason: `Non-identity claims leaked into act object: ${leakedClaims.join(", ")} — act should only contain identity claims (sub, act)`,
					expected: "act with only identity claims (sub, act)",
					actual: `act keys: ${Object.keys(act).join(", ")}`,
				};
			}

			// Verify act has sub
			if (!act.sub) {
				return {
					passed: false,
					reason: "act claim exists but has no sub field",
					expected: "act.sub identifying the current actor",
					actual: `act keys: ${Object.keys(act).join(", ")}`,
				};
			}

			// Check for nested act (indicating chain preservation)
			const nestedAct = act.act as Record<string, unknown> | undefined;
			if (nestedAct) {
				// Verify nested act also has sub and no leaked claims
				if (!nestedAct.sub) {
					return {
						passed: false,
						reason: "Nested act.act exists but has no sub field",
						expected: "act.act.sub identifying the prior actor",
						actual: `act.act keys: ${Object.keys(nestedAct).join(", ")}`,
					};
				}
				const nestedLeaked = Object.keys(nestedAct).filter((k) => NON_IDENTITY_CLAIMS.has(k));
				if (nestedLeaked.length > 0) {
					return {
						passed: false,
						reason: `Non-identity claims leaked into nested act: ${nestedLeaked.join(", ")}`,
						expected: "Nested act with only identity claims",
						actual: `act.act keys: ${Object.keys(nestedAct).join(", ")}`,
					};
				}
			}

			return {
				passed: true,
				reason: `act chain intact: act.sub="${act.sub}"${nestedAct ? `, act.act.sub="${nestedAct.sub}"` : " (single hop in act)"}`,
			};
		} catch {
			return {
				skipped: true,
				reason: "Resulting token is opaque (not a JWT) — cannot verify act nesting",
			};
		}
	},
};
