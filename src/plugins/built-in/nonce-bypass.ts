/**
 * Nonce Bypass Attack
 *
 * Manipulates or removes the nonce claim to test if clients properly validate
 * that tokens are bound to specific authentication requests.
 *
 * Real-world impact: Session fixation, replay attacks, CSRF
 *
 * Modes:
 * - remove: Removes the nonce claim entirely
 * - replay: Uses a predictable/static nonce value
 * - empty: Sets nonce to empty string
 * - mismatch: Changes nonce to a different random value
 *
 * Spec: OIDC Core 1.0 Section 3.1.3.7 - nonce MUST match value sent in request
 * CWE-384: Session Fixation
 */

import type { MischiefPlugin } from "../types.js";

type NonceMode = "remove" | "replay" | "empty" | "mismatch";

export const nonceBypassPlugin: MischiefPlugin = {
	id: "nonce-bypass",
	name: "Nonce Bypass",
	severity: "high",
	phase: "token-claims",

	spec: {
		oidc: "OIDC Core 1.0 Section 3.1.3.7",
		cwe: "CWE-384",
		description: "The 'nonce' claim MUST match the nonce value sent in the Authentication Request",
	},

	description: "Manipulates nonce claim to test replay protection",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const mode = (ctx.config.mode as NonceMode | undefined) ?? "remove";
		const originalNonce = ctx.token.claims.nonce as string | undefined;

		let newNonce: string | undefined;
		let mutation: string;

		switch (mode) {
			case "remove":
				newNonce = undefined;
				mutation = "Removed nonce claim";
				break;

			case "replay":
				// Use a static, predictable nonce that could be replayed
				newNonce =
					(ctx.config.replayNonce as string | undefined) ?? "static-predictable-nonce-12345";
				mutation = "Set nonce to predictable replay value";
				break;

			case "empty":
				newNonce = "";
				mutation = "Set nonce to empty string";
				break;

			case "mismatch":
				// Generate a different random nonce
				newNonce = `mismatched-nonce-${Date.now()}-${Math.random().toString(36).slice(2)}`;
				mutation = "Changed nonce to mismatched value";
				break;

			default:
				return {
					applied: false,
					mutation: `Unknown mode: ${mode}`,
					evidence: { mode },
				};
		}

		if (newNonce === undefined) {
			ctx.token.claims.nonce = undefined;
		} else {
			ctx.token.claims.nonce = newNonce;
		}

		return {
			applied: true,
			mutation,
			evidence: {
				mode,
				originalNonce: originalNonce ?? null,
				newNonce: newNonce ?? null,
				attackType: "nonce-bypass",
			},
		};
	},
};
