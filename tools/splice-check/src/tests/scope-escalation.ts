/**
 * Test 11: Scope Escalation Through Exchange (CD-02)
 *
 * A delegated token exchange should not grant broader scope than the
 * original subject_token. This test requests an elevated scope
 * (e.g., admin) during the exchange and verifies the AS rejects or
 * constrains it.
 */

import { describeResponse, isInconclusive, isSecurityRejection, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const scopeEscalation: AttackTest = {
	id: "scope-escalation",
	name: "Scope Escalation Through Exchange",
	description:
		"Requests a broader scope during token exchange than what the subject_token allows. " +
		"The AS should reject or constrain the scope to prevent privilege escalation.",
	spec: "RFC 8693 Section 2.1 (scope parameter)",
	severity: "high",

	async setup(ctx) {
		// Get Alice's token with limited scope
		ctx.log("Obtaining Alice's token (with standard scope)");
		const aliceToken = await ctx.client.clientCredentials("alice");

		return {
			tokens: { subjectToken: aliceToken },
		};
	},

	async attack(ctx, setup) {
		// Request elevated scope during exchange
		ctx.log("Attempting exchange with escalated scope (admin write delete)");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
			scope: "openid profile admin write delete", // Escalated beyond Alice's original scope
		});
	},

	verify(response) {
		if (isSecurityRejection(response)) {
			return {
				passed: true,
				reason: `AS rejected scope escalation — ${describeResponse(response)}`,
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
			const grantedScope = body?.scope as string | undefined;

			// Check if the AS constrained the scope (issued but with reduced scope)
			if (grantedScope) {
				const grantedScopes = new Set(grantedScope.split(" "));
				const hasEscalated =
					grantedScopes.has("admin") || grantedScopes.has("write") || grantedScopes.has("delete");

				if (!hasEscalated) {
					return {
						passed: true,
						reason: `AS constrained scope — requested "admin write delete" but granted "${grantedScope}"`,
					};
				}

				return {
					passed: false,
					reason: "AS granted escalated scope during token exchange",
					expected: "Scope rejection or scope-down (no admin/write/delete in delegated token)",
					actual: `Granted scope: "${grantedScope}" — privilege escalation possible`,
				};
			}

			// No scope in response — AS may have granted everything silently
			return {
				passed: false,
				reason:
					"AS accepted exchange with escalated scope request and did not return scope in response",
				expected: "Scope rejection or explicit scope-down",
				actual: `${describeResponse(response)} — no scope in response, privilege escalation may be possible`,
			};
		}

		return {
			passed: false,
			reason: "Unexpected response to scope escalation attempt",
			expected: "Scope rejection or scope constraint",
			actual: describeResponse(response),
		};
	},
};
