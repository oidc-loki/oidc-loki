/**
 * TE-11: Resource Parameter Abuse
 *
 * RFC 8693 Section 2.1: The `resource` parameter specifies the URI of the
 * target service where the token is intended to be used. The AS must validate
 * that the requesting client is authorized for the specified resource.
 *
 * This test sends an exchange targeting an internal/unauthorized resource URI
 * to verify the AS doesn't blindly mint tokens for any resource.
 */

import { describeResponse, isInconclusive, isSecurityRejection, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const resourceAbuse: AttackTest = {
	id: "resource-abuse",
	name: "Resource Parameter Abuse",
	description:
		"Requests a token exchange with a resource URI targeting an internal service. " +
		"The AS must validate that the client is authorized for the specified resource.",
	spec: "RFC 8693 Section 2.1",
	severity: "high",

	async setup(ctx) {
		ctx.log("Obtaining Alice's access_token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		return {
			tokens: { subjectToken: aliceToken },
		};
	},

	async attack(ctx, setup) {
		ctx.log("Requesting exchange with resource targeting an internal service URI");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			resource: "https://internal-admin-api.corp.example.com",
			clientName: "agent-n",
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS validated resource parameter — ${describeResponse(response)}`,
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
						"AS issued token for unauthorized resource URI — " +
						"any client can mint tokens for any service",
					expected: "Rejection with invalid_target",
					actual: `${describeResponse(response)} — token issued for internal resource`,
				};
			}
		}

		return {
			passed: false,
			reason: "Unexpected response to unauthorized resource targeting",
			expected: "Rejection with invalid_target",
			actual: describeResponse(response),
		};
	},
};
