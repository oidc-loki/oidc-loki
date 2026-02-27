/**
 * TE-14: `issued_token_type` Response Validation
 *
 * RFC 8693 Section 2.2.1: The `issued_token_type` field is REQUIRED in the
 * token exchange response. It tells the client what type of token was actually
 * issued. An AS that omits it violates a MUST-level requirement.
 */

import { describeResponse, isInconclusive, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

const VALID_TOKEN_TYPES = new Set([
	TOKEN_TYPE.ACCESS_TOKEN,
	TOKEN_TYPE.REFRESH_TOKEN,
	TOKEN_TYPE.ID_TOKEN,
	TOKEN_TYPE.JWT,
]);

export const issuedTokenTypeValidation: AttackTest = {
	id: "issued-token-type-validation",
	name: "issued_token_type Response Validation",
	description:
		"Verifies that a successful token exchange response includes the required " +
		"`issued_token_type` field with a valid token type URI.",
	spec: "RFC 8693 Section 2.2.1",
	severity: "medium",

	async setup(ctx) {
		ctx.log("Obtaining Alice's access_token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		return {
			tokens: { subjectToken: aliceToken },
		};
	},

	async attack(ctx, setup) {
		ctx.log("Performing baseline token exchange to validate response format");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
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
				reason: `Exchange was rejected — ${describeResponse(response)}. Cannot validate response format.`,
			};
		}

		const body = jsonBody(response);
		if (!body?.access_token) {
			return {
				passed: false,
				reason: "Exchange returned 200 but no access_token",
				expected: "access_token and issued_token_type in response",
				actual: describeResponse(response),
			};
		}

		const issuedType = body.issued_token_type as string | undefined;
		if (!issuedType) {
			return {
				passed: false,
				reason:
					"Response missing required `issued_token_type` field — " +
					"violates RFC 8693 Section 2.2.1 MUST requirement",
				expected: "issued_token_type field in response",
				actual: `Response keys: ${Object.keys(body).join(", ")} (no issued_token_type)`,
			};
		}

		if (!VALID_TOKEN_TYPES.has(issuedType as (typeof TOKEN_TYPE)[keyof typeof TOKEN_TYPE])) {
			return {
				passed: false,
				reason: `issued_token_type has unrecognized value: "${issuedType}"`,
				expected: "One of the standard token type URIs",
				actual: issuedType,
			};
		}

		return {
			passed: true,
			reason: `Response includes valid issued_token_type: ${issuedType}`,
		};
	},
};
