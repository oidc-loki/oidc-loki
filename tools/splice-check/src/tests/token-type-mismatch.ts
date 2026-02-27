/**
 * TE-01: Token Type Indicator Mismatch
 *
 * RFC 8693 Section 2.1: "The authorization server MUST perform the appropriate
 * validation procedures for the indicated token type."
 *
 * An attacker presents an access_token but declares it as an id_token type.
 * If the AS blindly trusts the type indicator, it may apply the wrong
 * validation rules — skipping audience checks that apply to access tokens,
 * or treating an id_token as an access credential.
 */

import { describeResponse, isInconclusive, isSecurityRejection } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const tokenTypeMismatch: AttackTest = {
	id: "token-type-mismatch",
	name: "Token Type Indicator Mismatch",
	description:
		"Presents an access_token but declares it as subject_token_type=id_token. " +
		"The AS MUST validate tokens against their declared type.",
	spec: "RFC 8693 Section 2.1",
	severity: "critical",

	async setup(ctx) {
		ctx.log("Obtaining Alice's access_token via client_credentials");
		const aliceToken = await ctx.client.clientCredentials("alice");

		const agentAToken = await ctx.client.clientCredentials("agent-a");

		return {
			tokens: {
				subjectToken: aliceToken,
				actorToken: agentAToken,
			},
		};
	},

	async attack(ctx, setup) {
		ctx.log("Exchanging with subject_token_type=id_token (but token is an access_token)");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			// LIE: declare access_token as id_token
			subject_token_type: TOKEN_TYPE.ID_TOKEN,
			actor_token: requireToken(setup, "actorToken"),
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS validated token against declared type — ${describeResponse(response)}`,
			};
		}

		if (isInconclusive(response)) {
			return {
				skipped: true,
				reason: `Inconclusive: ${describeResponse(response)}`,
			};
		}

		return {
			passed: false,
			reason:
				"AS accepted access_token declared as id_token — " +
				"token type indicators are not validated",
			expected: "Rejection (token content does not match declared type)",
			actual: `${describeResponse(response)} — type mismatch not detected`,
		};
	},
};
