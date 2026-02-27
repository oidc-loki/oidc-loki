/**
 * TE-05: act Claim Stripping / Delegation-to-Impersonation Downgrade
 *
 * RFC 8693 Sections 1.1 and 4.1: Delegation tokens contain an `act` claim
 * recording who is acting on behalf of the subject. If an attacker re-exchanges
 * a delegation token WITHOUT an actor_token, the AS may strip the `act` claim,
 * converting delegation into impersonation and destroying the audit trail.
 *
 * Related: CVE-2025-55241 (Microsoft Entra ID) — act claim manipulation
 * leading to cross-tenant impersonation.
 */

import { decodeJwt } from "jose";
import { describeResponse, isInconclusive, isSecurityRejection, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const actClaimStripping: AttackTest = {
	id: "act-claim-stripping",
	name: "act Claim Stripping",
	description:
		"Re-exchanges a delegation token (with act claim) without an actor_token. " +
		"The AS should reject or preserve the act claim — not strip it.",
	spec: "RFC 8693 Section 4.1 / CVE-2025-55241",
	severity: "critical",

	async setup(ctx) {
		// Step 1: Get Alice's token
		ctx.log("Obtaining Alice's token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		// Step 2: Perform delegation exchange to get a token with act claim
		ctx.log("Performing delegation exchange (Alice → Agent A) to get token with act claim");
		const agentAToken = await ctx.client.clientCredentials("agent-a");
		const exchangeResponse = await ctx.client.tokenExchange({
			subject_token: aliceToken,
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: agentAToken,
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
		});

		if (exchangeResponse.status !== 200) {
			throw new Error(`Setup: delegation exchange failed (HTTP ${exchangeResponse.status})`);
		}

		const body = jsonBody(exchangeResponse);
		const delegationToken = body?.access_token as string | undefined;
		if (!delegationToken) {
			throw new Error("Setup: delegation exchange returned no access_token");
		}

		// Step 3: Check if the delegation token actually has an act claim
		let hasActClaim = false;
		try {
			const claims = decodeJwt(delegationToken);
			hasActClaim = claims.act !== undefined;
			ctx.log(`Delegation token has act claim: ${hasActClaim}`);
		} catch {
			ctx.log("Could not decode delegation token — may be opaque");
		}

		return {
			tokens: { delegationToken },
			metadata: { hasActClaim },
		};
	},

	async attack(ctx, setup) {
		// Re-exchange the delegation token WITHOUT an actor_token
		// This requests impersonation semantics from a delegation token
		ctx.log("Re-exchanging delegation token WITHOUT actor_token (attempting act stripping)");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "delegationToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			// Deliberately NO actor_token — requesting impersonation
			clientName: "agent-n",
		});
	},

	verify(response, setup) {
		const hasActClaim = setup.metadata?.hasActClaim as boolean | undefined;

		// If the AS rejects the re-exchange entirely: PASS
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS rejected delegation-to-impersonation downgrade — ${describeResponse(response)}`,
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
			const resultToken = body?.access_token as string | undefined;

			if (!resultToken) {
				return {
					passed: false,
					reason: "AS returned 200 but no access_token",
					expected: "Rejection or token preserving act claim",
					actual: describeResponse(response),
				};
			}

			// If original had act claim, check if it was preserved
			if (hasActClaim) {
				try {
					const claims = decodeJwt(resultToken);
					if (claims.act !== undefined) {
						return {
							passed: true,
							reason:
								"AS preserved act claim during re-exchange — " +
								"delegation audit trail maintained",
						};
					}
					return {
						passed: false,
						reason:
							"AS stripped act claim during re-exchange — " +
							"delegation converted to impersonation, audit trail destroyed",
						expected: "act claim preserved or exchange rejected",
						actual: "Token issued without act claim (impersonation)",
					};
				} catch {
					return {
						skipped: true,
						reason:
							"Could not decode result token to verify act claim preservation — " +
							"token may be opaque",
					};
				}
			}

			// Original didn't have act claim — just report that AS allowed impersonation
			return {
				passed: false,
				reason:
					"AS accepted re-exchange of delegation token as impersonation — " +
					"no act claim in original, but impersonation should still be restricted",
				expected: "Rejection (agent-n not authorized for impersonation)",
				actual: `${describeResponse(response)} — impersonation token issued`,
			};
		}

		return {
			passed: false,
			reason: "Unexpected response to act claim stripping attempt",
			expected: "Rejection or token with preserved act claim",
			actual: describeResponse(response),
		};
	},
};
