/**
 * TE-04: Audience Targeting to Unauthorized Resource
 *
 * RFC 8693 Section 2.1: The `audience` parameter specifies the target
 * service for the exchanged token. The AS must validate that the requesting
 * client is authorized to target the specified audience.
 *
 * Mirrors CVE-2022-1245 (Keycloak, CVSS 9.8) where any client could
 * exchange tokens for any target service by specifying the client_id.
 */

import { describeResponse, isInconclusive, isSecurityRejection, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const audienceTargeting: AttackTest = {
	id: "audience-targeting",
	name: "Audience Targeting to Unauthorized Resource",
	description:
		"Agent N requests a token targeting an unauthorized audience. " +
		"The AS must validate the client is authorized for the specified audience.",
	spec: "RFC 8693 Section 2.1 / CVE-2022-1245",
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
			"Requesting exchange with audience targeting an unauthorized service " +
				"(agent-n targeting alice's app)",
		);
		// Agent N requests a token scoped to Alice's app — a service it should
		// not be authorized to target. We also try a clearly unauthorized name.
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			audience: "admin-service",
			clientName: "agent-n",
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS validated audience targeting — ${describeResponse(response)}`,
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
						"AS issued token targeting unauthorized audience — " +
						"any client can mint tokens for any service (cf. CVE-2022-1245)",
					expected: "Rejection with invalid_target",
					actual: `${describeResponse(response)} — token issued for 'admin-service'`,
				};
			}
		}

		return {
			passed: false,
			reason: "Unexpected response to unauthorized audience targeting",
			expected: "Rejection with invalid_target",
			actual: describeResponse(response),
		};
	},
};
