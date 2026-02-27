/**
 * TE-06: Expired Token Exchange
 *
 * RFC 8693 Section 2.1: The AS must validate the subject_token before issuing
 * a new token. If the subject_token has expired, the exchange must be rejected.
 * Accepting expired tokens allows attackers to re-activate stale credentials.
 *
 * This test submits a fabricated JWT with exp in the past as the subject_token.
 */

import { describeResponse, isInconclusive, isSecurityRejection, jsonBody } from "./classify.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

// A fabricated JWT with exp in the past — unsigned, header {"alg":"none","typ":"JWT"}
// Payload: {"sub":"alice","exp":1000000000} (Sep 2001 — clearly expired)
const EXPIRED_JWT =
	"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImV4cCI6MTAwMDAwMDAwMH0.";

export const expiredTokenExchange: AttackTest = {
	id: "expired-token-exchange",
	name: "Expired Token Exchange",
	description:
		"Submits a fabricated JWT with an expired `exp` claim as subject_token. " +
		"The AS must reject expired tokens to prevent credential re-activation.",
	spec: "RFC 8693 Section 2.1",
	severity: "high",

	async setup(ctx) {
		ctx.log("No setup needed — using fabricated expired JWT");
		return { tokens: {} };
	},

	async attack(ctx) {
		ctx.log("Submitting expired JWT as subject_token");
		return ctx.client.tokenExchange({
			subject_token: EXPIRED_JWT,
			subject_token_type: TOKEN_TYPE.JWT,
			clientName: "agent-a",
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS rejected expired token — ${describeResponse(response)}`,
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
						"AS accepted an expired JWT as subject_token — " +
						"stale credentials can be re-activated via token exchange",
					expected: "Rejection of expired subject_token",
					actual: `${describeResponse(response)} — new token issued from expired JWT`,
				};
			}
		}

		return {
			passed: false,
			reason: "Unexpected response to expired token exchange",
			expected: "Rejection of expired subject_token",
			actual: describeResponse(response),
		};
	},
};
