/**
 * Test 7: Refresh Token Bypass
 *
 * If a delegated token exchange returns a refresh_token, refreshing that
 * token should re-validate the delegation context. Otherwise, an attacker
 * who obtained a refresh_token from a spliced exchange could perpetually
 * refresh it even after the original delegation is revoked.
 *
 * This test:
 *   1. Obtains Alice's token and performs a legitimate delegation exchange
 *   2. Captures the refresh_token from the exchange
 *   3. Revokes Alice's original token (invalidating the delegation context)
 *   4. Attempts to use the refresh_token after revocation
 *   5. PASS if the AS rejects the refresh (delegation-aware)
 *   6. FAIL if the AS still issues a new token (context not re-validated)
 */

import { describeResponse, isInconclusive, isSecurityRejection, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const refreshBypass: AttackTest = {
	id: "refresh-bypass",
	name: "Refresh Token Bypass",
	description:
		"Revokes the original subject_token, then attempts to refresh a delegated token. " +
		"The AS should reject the refresh because the delegation context has been invalidated.",
	spec: "RFC 8693 Section 2.1 + RFC 6749 Section 6",
	severity: "medium",

	async setup(ctx) {
		// Get Alice's token
		ctx.log("Obtaining Alice's token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		// Perform legitimate exchange and capture refresh_token
		ctx.log("Performing legitimate exchange to obtain refresh_token");
		const exchangeResponse = await ctx.client.tokenExchange({
			subject_token: aliceToken,
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
			scope: "openid offline_access",
		});

		if (exchangeResponse.status !== 200) {
			throw new Error(`Setup: token exchange failed (HTTP ${exchangeResponse.status})`);
		}

		const body = jsonBody(exchangeResponse);
		const refreshToken = body?.refresh_token as string | undefined;

		if (!refreshToken) {
			throw new Error(
				"Setup: token exchange did not return refresh_token. " +
					"Ensure the AS is configured to issue refresh tokens for delegated exchanges " +
					"(offline_access scope may be required).",
			);
		}

		ctx.log("Obtained refresh_token from delegated exchange");

		return {
			tokens: {
				aliceToken,
				refreshToken,
			},
		};
	},

	async attack(ctx, setup) {
		// Step 1: Revoke Alice's original token to invalidate delegation context
		ctx.log("Revoking Alice's original token to invalidate delegation context");
		const revokeResponse = await ctx.client.revokeToken(
			requireToken(setup, "aliceToken"),
			"alice",
			"access_token",
		);
		ctx.log(`Revocation response: HTTP ${revokeResponse.status}`);

		// Step 2: Attempt to refresh the delegated token after revocation
		ctx.log("Attempting to refresh delegated token after upstream revocation");
		return ctx.client.refreshToken(requireToken(setup, "refreshToken"), "agent-a");
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS re-validated delegation context on refresh — ${describeResponse(response)}`,
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
						"AS issued new token via refresh after upstream token was revoked — " +
						"delegation context not re-validated",
					expected: "Refresh rejection after upstream revocation",
					actual: `${describeResponse(response)} — new access_token issued`,
				};
			}
		}

		return {
			passed: false,
			reason: "Unexpected response from refresh attempt after upstream revocation",
			expected: "Security rejection (delegation context invalidated)",
			actual: describeResponse(response),
		};
	},
};
