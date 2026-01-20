/**
 * State Bypass Attack
 *
 * This plugin manipulates tokens to simulate scenarios where state validation
 * might be bypassed. While state is primarily an authorization request parameter,
 * some implementations embed state-related claims in tokens.
 *
 * Real-world impact: CSRF attacks on OAuth flows
 *
 * Modes:
 * - inject-state: Injects a state claim into the token
 * - tamper-azp: Manipulates the authorized party (azp) claim
 * - add-claims: Adds unexpected claims that might confuse parsers
 *
 * Spec: RFC 6749 Section 10.12 - state parameter for CSRF protection
 * OIDC: OpenID Connect Core 1.0 Section 3.1.2.1 - state MUST match
 * CWE-352: Cross-Site Request Forgery (CSRF)
 */

import type { MischiefPlugin } from "../types.js";

type StateMode = "inject-state" | "tamper-azp" | "add-claims";

export const stateBypassPlugin: MischiefPlugin = {
	id: "state-bypass",
	name: "State/CSRF Bypass",
	severity: "high",
	phase: "token-claims",

	spec: {
		rfc: "RFC 6749 Section 10.12",
		oidc: "OIDC Core 1.0 Section 3.1.2.1",
		cwe: "CWE-352",
		description: "The 'state' parameter MUST be validated to prevent CSRF attacks",
	},

	description: "Manipulates state-related claims to test CSRF protection",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const mode = (ctx.config.mode as StateMode | undefined) ?? "tamper-azp";
		const evidence: Record<string, unknown> = { mode };

		let mutation: string;

		switch (mode) {
			case "inject-state": {
				// Inject a state claim into the token (non-standard but sometimes checked)
				const injectedState =
					(ctx.config.injectedState as string | undefined) ?? "attacker-controlled-state";
				ctx.token.claims.state = injectedState;
				mutation = "Injected state claim into token";
				evidence.injectedState = injectedState;
				break;
			}

			case "tamper-azp": {
				// Manipulate the authorized party claim
				const originalAzp = ctx.token.claims.azp;
				const maliciousAzp =
					(ctx.config.maliciousAzp as string | undefined) ?? "malicious-client-id";
				ctx.token.claims.azp = maliciousAzp;
				mutation = "Changed azp (authorized party) claim";
				evidence.originalAzp = originalAzp ?? null;
				evidence.newAzp = maliciousAzp;
				break;
			}

			case "add-claims": {
				// Add unexpected claims that might confuse token parsers
				const unexpectedClaims = {
					_debug: true,
					admin: true,
					role: "superuser",
					permissions: ["*"],
					bypass_validation: true,
				};
				for (const [key, value] of Object.entries(unexpectedClaims)) {
					ctx.token.claims[key] = value;
				}
				mutation = "Added unexpected claims to confuse parsers";
				evidence.addedClaims = Object.keys(unexpectedClaims);
				break;
			}

			default:
				return {
					applied: false,
					mutation: `Unknown mode: ${mode}`,
					evidence: { mode },
				};
		}

		evidence.attackType = "state-bypass";

		return {
			applied: true,
			mutation,
			evidence,
		};
	},
};
