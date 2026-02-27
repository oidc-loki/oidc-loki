/**
 * TE-02: Unauthenticated Token Exchange
 *
 * RFC 8693 Section 5: "Omitting client authentication allows for a compromised
 * token to be leveraged via an STS into other tokens by anyone possessing
 * the compromised token."
 *
 * Sends a token exchange request with NO client authentication. If the AS
 * processes the exchange, any party with a stolen token can mint new tokens.
 */

import { describeResponse, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { GRANT_TYPE_TOKEN_EXCHANGE, TOKEN_TYPE } from "./types.js";

export const unauthenticatedExchange: AttackTest = {
	id: "unauthenticated-exchange",
	name: "Unauthenticated Token Exchange",
	description:
		"Sends a token exchange request without any client authentication. " +
		"The AS MUST require client authentication for token exchange.",
	spec: "RFC 8693 Section 5",
	severity: "critical",

	async setup(ctx) {
		ctx.log("Obtaining Alice's token for use as subject_token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		return {
			tokens: { subjectToken: aliceToken },
		};
	},

	async attack(ctx, setup) {
		ctx.log("Sending token exchange request with NO client authentication");
		const params = new URLSearchParams({
			grant_type: GRANT_TYPE_TOKEN_EXCHANGE,
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
		});
		// No client_id, no client_secret, no Authorization header
		return ctx.client.rawTokenExchange(params);
	},

	verify(response) {
		// 401 is the expected response for missing client auth
		if (response.status === 401) {
			return {
				passed: true,
				reason: `AS requires client authentication — ${describeResponse(response)}`,
			};
		}

		// Some AS implementations return 400 with invalid_client
		const body = jsonBody(response);
		const errorCode = typeof body?.error === "string" ? body.error : undefined;
		if ((response.status === 400 || response.status === 403) && errorCode === "invalid_client") {
			return {
				passed: true,
				reason: `AS rejected unauthenticated request — ${describeResponse(response)}`,
			};
		}

		// If the AS returned a token, client auth is not enforced
		if (response.status === 200 && body?.access_token) {
			return {
				passed: false,
				reason:
					"AS accepted token exchange without client authentication — " +
					"any party with a stolen token can mint new tokens",
				expected: "HTTP 401 (client authentication required)",
				actual: `${describeResponse(response)} — access_token issued without client auth`,
			};
		}

		// 429/500 are inconclusive
		if (response.status === 429 || response.status >= 500) {
			return {
				skipped: true,
				reason: `Inconclusive: ${describeResponse(response)}`,
			};
		}

		// Any other rejection is a pass (AS didn't accept the unauthenticated request)
		if (response.status >= 400) {
			return {
				passed: true,
				reason: `AS rejected unauthenticated request — ${describeResponse(response)}`,
			};
		}

		return {
			passed: false,
			reason: "Unexpected response to unauthenticated token exchange",
			expected: "HTTP 401 or 400 with invalid_client",
			actual: describeResponse(response),
		};
	},
};
