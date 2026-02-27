/**
 * TE-10: Cross-Issuer Token Acceptance
 *
 * RFC 8693 Section 2.1: The AS must validate that the subject_token was issued
 * by a trusted issuer. If the AS accepts tokens from any issuer without
 * verification, an attacker can mint tokens from a rogue AS.
 *
 * This test submits a fabricated token string (not from the target AS) as the
 * subject_token. A secure AS will reject it because it cannot validate the
 * token's signature or issuer.
 */

import { describeResponse, isInconclusive, isSecurityRejection, jsonBody } from "./classify.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

// A fabricated JWT with a fake issuer — unsigned, header {"alg":"none","typ":"JWT"}
// Payload: {"sub":"alice","iss":"https://evil-issuer.example.com","aud":"target","exp":9999999999}
const FAKE_ISSUER_JWT =
	"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
	"eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vZXZpbC1pc3N1ZXIuZXhhbXBsZS5jb20iLCJhdWQiOiJ0YXJnZXQiLCJleHAiOjk5OTk5OTk5OTl9.";

export const issuerValidation: AttackTest = {
	id: "issuer-validation",
	name: "Cross-Issuer Token Acceptance",
	description:
		"Submits a fabricated token with a fake issuer as subject_token. " +
		"The AS must reject tokens it did not issue.",
	spec: "RFC 8693 Section 2.1",
	severity: "critical",

	async setup(ctx) {
		ctx.log("No setup needed — using fabricated token with fake issuer");
		return { tokens: {} };
	},

	async attack(ctx) {
		ctx.log("Submitting fabricated token with fake issuer as subject_token");
		return ctx.client.tokenExchange({
			subject_token: FAKE_ISSUER_JWT,
			subject_token_type: TOKEN_TYPE.JWT,
			clientName: "agent-a",
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS rejected foreign-issuer token — ${describeResponse(response)}`,
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
						"AS accepted a fabricated token from a fake issuer — " +
						"no issuer or signature validation on subject_token",
					expected: "Rejection of token with unrecognized issuer",
					actual: `${describeResponse(response)} — token issued for foreign JWT`,
				};
			}
		}

		return {
			passed: false,
			reason: "Unexpected response to foreign-issuer token",
			expected: "Rejection of token with unrecognized issuer",
			actual: describeResponse(response),
		};
	},
};
