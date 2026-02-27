/**
 * TE-03: Requested Token Type Escalation
 *
 * RFC 8693 Section 2.1: The `requested_token_type` parameter lets the client
 * specify what type of token it wants. An attacker can use this to escalate
 * from a short-lived access_token to a long-lived refresh_token.
 *
 * Related: CVE-2022-1245 (Keycloak) where insufficient input validation
 * in token exchange led to CVSS 9.8 privilege escalation.
 */

import { describeResponse, isInconclusive, isSecurityRejection, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const tokenTypeEscalation: AttackTest = {
	id: "token-type-escalation",
	name: "Requested Token Type Escalation",
	description:
		"Requests a refresh_token via requested_token_type when exchanging an access_token. " +
		"An AS should not convert short-lived access into long-lived refresh credentials.",
	spec: "RFC 8693 Section 2.1",
	severity: "critical",

	async setup(ctx) {
		ctx.log("Obtaining Alice's access_token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		return {
			tokens: { subjectToken: aliceToken },
		};
	},

	async attack(ctx, setup) {
		ctx.log(
			"Requesting refresh_token type via requested_token_type " +
				"(escalation from access_token to refresh_token)",
		);
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			requested_token_type: TOKEN_TYPE.REFRESH_TOKEN,
			clientName: "agent-a",
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS rejected token type escalation — ${describeResponse(response)}`,
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
			const issuedType = body?.issued_token_type as string | undefined;

			// Check if AS actually issued a refresh token
			if (body?.refresh_token || issuedType === TOKEN_TYPE.REFRESH_TOKEN) {
				return {
					passed: false,
					reason:
						"AS escalated access_token to refresh_token — " +
						"short-lived credential converted to long-lived persistence",
					expected: "Rejection of token type escalation",
					actual: `${describeResponse(response)} — refresh_token issued`,
				};
			}

			// AS accepted but issued an access_token instead (downgraded the request)
			if (body?.access_token && issuedType !== TOKEN_TYPE.REFRESH_TOKEN) {
				return {
					passed: true,
					reason:
						"AS accepted exchange but issued access_token (not refresh_token) — " +
						"type escalation was constrained",
				};
			}
		}

		return {
			passed: false,
			reason: "Unexpected response to token type escalation request",
			expected: "Rejection or constrained token type",
			actual: describeResponse(response),
		};
	},
};
