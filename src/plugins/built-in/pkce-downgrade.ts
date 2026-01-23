/**
 * PKCE Downgrade Attack
 *
 * Tests client handling of PKCE (Proof Key for Code Exchange) bypass attempts.
 * This plugin manipulates token claims to simulate scenarios where PKCE
 * validation might be circumvented.
 *
 * Real-world impact: Mobile/SPA authorization code interception
 *
 * Modes:
 * - inject-code-challenge: Adds code_challenge claim to token (non-standard)
 * - weaken-method: Indicates plain method was used instead of S256
 * - add-auth-time: Manipulates auth_time to suggest different auth context
 *
 * Note: True PKCE attacks happen at the authorization/token exchange level,
 * not in the token itself. This plugin tests if clients incorrectly trust
 * PKCE-related claims in tokens.
 *
 * Spec: RFC 7636 - Proof Key for Code Exchange
 * CWE-345: Insufficient Verification of Data Authenticity
 */

import type { MischiefPlugin } from "../types.js";

type PkceMode = "inject-code-challenge" | "weaken-method" | "add-auth-time";

export const pkceDowngradePlugin: MischiefPlugin = {
	id: "pkce-downgrade",
	name: "PKCE Downgrade",
	severity: "high",
	phase: "token-claims",

	spec: {
		rfc: "RFC 7636",
		cwe: "CWE-345",
		description: "PKCE code_challenge_method SHOULD be S256, clients MUST verify code_verifier",
	},

	description: "Tests PKCE-related claim handling and auth context validation",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const mode = (ctx.config.mode as PkceMode | undefined) ?? "weaken-method";
		const evidence: Record<string, unknown> = { mode };

		let mutation: string;

		switch (mode) {
			case "inject-code-challenge": {
				// Inject PKCE-related claims (non-standard but might confuse some implementations)
				ctx.token.claims.code_challenge = "attacker-controlled-challenge";
				ctx.token.claims.code_challenge_method = "plain";
				mutation = "Injected code_challenge claims into token";
				evidence.injectedClaims = ["code_challenge", "code_challenge_method"];
				break;
			}

			case "weaken-method": {
				// Add claims suggesting weaker PKCE was used
				ctx.token.claims.acr = "0"; // Authentication Context Class = no assurance
				ctx.token.claims.amr = ["pwd"]; // Only password, no MFA
				mutation = "Set weak authentication context (acr=0, amr=[pwd])";
				evidence.acr = "0";
				evidence.amr = ["pwd"];
				break;
			}

			case "add-auth-time": {
				// Manipulate auth_time to suggest stale authentication
				const staleAuthTime = Math.floor(Date.now() / 1000) - 86400 * 30; // 30 days ago
				const originalAuthTime = ctx.token.claims.auth_time;
				ctx.token.claims.auth_time = staleAuthTime;
				mutation = "Set auth_time to 30 days ago (stale session)";
				evidence.originalAuthTime = originalAuthTime ?? null;
				evidence.newAuthTime = staleAuthTime;
				break;
			}

			default:
				return {
					applied: false,
					mutation: `Unknown mode: ${mode}`,
					evidence: { mode },
				};
		}

		evidence.attackType = "pkce-downgrade";

		return {
			applied: true,
			mutation,
			evidence,
		};
	},
};
