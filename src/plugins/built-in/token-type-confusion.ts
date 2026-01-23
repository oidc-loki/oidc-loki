/**
 * Token Type Confusion Attack
 *
 * Manipulates the typ header to test if clients properly distinguish
 * between different token types (access tokens vs ID tokens).
 *
 * Real-world impact: Using access tokens as ID tokens or vice versa
 *
 * Modes:
 * - remove: Removes the typ header entirely
 * - invalid: Sets typ to an invalid value
 * - swap: Swaps JWT to at+jwt or vice versa (token type confusion)
 * - lowercase: Changes typ case (JWT vs jwt vs Jwt)
 *
 * Spec: RFC 9068 - JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
 * Spec: RFC 7519 Section 5.1 - "typ" header parameter
 * CWE-843: Access of Resource Using Incompatible Type ('Type Confusion')
 */

import type { MischiefPlugin } from "../types.js";

type TokenTypeMode = "remove" | "invalid" | "swap" | "lowercase";

export const tokenTypeConfusionPlugin: MischiefPlugin = {
	id: "token-type-confusion",
	name: "Token Type Confusion",
	severity: "high",
	phase: "token-signing",

	spec: {
		rfc: "RFC 9068, RFC 7519 Section 5.1",
		cwe: "CWE-843",
		description: "The 'typ' header MUST be validated to distinguish access tokens from ID tokens",
	},

	description: "Manipulates typ header to test token type validation",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const mode = (ctx.config.mode as TokenTypeMode | undefined) ?? "swap";
		const originalTyp = ctx.token.header.typ;

		let newTyp: string | undefined;
		let mutation: string;

		switch (mode) {
			case "remove":
				newTyp = undefined;
				mutation = "Removed typ header";
				break;

			case "invalid":
				newTyp = (ctx.config.invalidTyp as string | undefined) ?? "INVALID";
				mutation = `Set typ to invalid value '${newTyp}'`;
				break;

			case "swap": {
				// Swap between JWT and at+jwt to test type confusion
				if (originalTyp === "at+jwt" || originalTyp === "application/at+jwt") {
					newTyp = "JWT";
					mutation = "Swapped typ from at+jwt to JWT (access token as generic JWT)";
				} else {
					newTyp = "at+jwt";
					mutation = "Swapped typ from JWT to at+jwt (generic JWT as access token)";
				}
				break;
			}

			case "lowercase": {
				// Test case sensitivity
				if (originalTyp === "JWT") {
					newTyp = "jwt";
				} else if (originalTyp === "jwt") {
					newTyp = "Jwt";
				} else {
					newTyp = "jwt";
				}
				mutation = `Changed typ case from '${originalTyp ?? "undefined"}' to '${newTyp}'`;
				break;
			}

			default:
				return {
					applied: false,
					mutation: `Unknown mode: ${mode}`,
					evidence: { mode },
				};
		}

		// For remove mode, delete the typ header; otherwise set the new value
		if (newTyp === undefined) {
			(ctx.token.header as Record<string, unknown>).typ = undefined;
		} else {
			ctx.token.header.typ = newTyp;
		}

		return {
			applied: true,
			mutation,
			evidence: {
				mode,
				originalTyp: originalTyp ?? null,
				newTyp: newTyp ?? null,
				attackType: "token-type-confusion",
			},
		};
	},
};
