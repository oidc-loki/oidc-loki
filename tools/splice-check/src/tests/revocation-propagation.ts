/**
 * Test 8: Revocation Propagation
 *
 * When the original subject_token is revoked, any downstream delegated
 * tokens should also become invalid. If they don't, an attacker who
 * obtained a downstream token can continue using it after the user
 * revokes consent.
 */

import { jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const revocationPropagation: AttackTest = {
	id: "revocation-propagation",
	name: "Revocation Propagation",
	description:
		"Tests whether revoking the original subject_token invalidates downstream " +
		"delegated tokens. Delegation chains should honor revocation propagation.",
	spec: "RFC 8693 Section 2.1 + RFC 7009",
	severity: "medium",

	async setup(ctx) {
		// Get Alice's token
		ctx.log("Obtaining Alice's token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		// Exchange to get a delegated token
		ctx.log("Performing delegation exchange: Alice → Agent A");
		const exchangeResponse = await ctx.client.tokenExchange({
			subject_token: aliceToken,
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
		});

		if (exchangeResponse.status !== 200) {
			throw new Error(`Setup: delegation exchange failed (HTTP ${exchangeResponse.status})`);
		}

		const body = jsonBody(exchangeResponse);
		const delegatedToken = body?.access_token as string | undefined;
		if (!delegatedToken) {
			throw new Error("Setup: delegation exchange returned 200 but no access_token");
		}

		return {
			tokens: {
				originalToken: aliceToken,
				delegatedToken,
			},
		};
	},

	async attack(ctx, setup) {
		// Step 1: Revoke the original token
		ctx.log("Revoking original subject_token");
		const revokeResponse = await ctx.client.revokeToken(
			requireToken(setup, "originalToken"),
			"alice",
			"access_token",
		);
		ctx.log(`Revocation response: HTTP ${revokeResponse.status}`);

		// Step 2: Try to use the downstream delegated token via introspection
		ctx.log("Introspecting downstream delegated token after revocation");
		return ctx.client.introspectToken(requireToken(setup, "delegatedToken"), "agent-a");
	},

	verify(response) {
		// If introspection is supported, check whether the token is marked inactive
		if (response.status === 200) {
			const body = jsonBody(response);
			if (body?.active === false) {
				return {
					passed: true,
					reason: "Downstream token correctly marked inactive after upstream revocation",
				};
			}
			if (body?.active === true) {
				return {
					passed: false,
					reason: "Downstream token still active after upstream token revocation",
					expected: "Introspection returns active=false",
					actual: "Introspection returns active=true — revocation did not propagate",
				};
			}
		}

		// Introspection not supported or returned error
		if (response.status === 401 || response.status === 403) {
			return {
				skipped: true,
				reason:
					"Token introspection returned auth error — " +
					"cannot determine revocation propagation without introspection support",
			};
		}

		if (response.status >= 400) {
			return {
				skipped: true,
				reason: `Introspection endpoint returned HTTP ${response.status} — revocation propagation cannot be verified without a working introspection endpoint`,
			};
		}

		return {
			skipped: true,
			reason: `Unexpected introspection response (HTTP ${response.status}) — cannot determine propagation`,
		};
	},
};
