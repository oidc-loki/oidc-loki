/**
 * Key ID (kid) Manipulation Attack
 *
 * Manipulates the key ID header to test if clients properly validate
 * which key was used to sign the token.
 *
 * Real-world impact: Key confusion, signature bypass during key rollover
 *
 * Modes:
 * - remove: Removes the kid header entirely
 * - invalid: Sets kid to a non-existent key ID
 * - injection: Sets kid to a path traversal or injection payload
 * - sql: Sets kid to SQL injection payload (some implementations query DB)
 *
 * Spec: RFC 7517 Section 4.5 - kid identifies the key used
 * CWE-347: Improper Verification of Cryptographic Signature
 */

import type { MischiefPlugin } from "../types.js";

type KidMode = "remove" | "invalid" | "injection" | "sql";

export const kidManipulationPlugin: MischiefPlugin = {
	id: "kid-manipulation",
	name: "Key ID Manipulation",
	severity: "high",
	phase: "token-signing",

	spec: {
		rfc: "RFC 7517 Section 4.5",
		cwe: "CWE-347",
		description: "The 'kid' header MUST match a key in the JWKS and be validated",
	},

	description: "Manipulates kid header to test key selection validation",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const mode = (ctx.config.mode as KidMode | undefined) ?? "invalid";
		const originalKid = ctx.token.header.kid;

		let newKid: string;
		let mutation: string;

		switch (mode) {
			case "remove":
				newKid = ""; // Empty string simulates removal
				mutation = "Removed kid header (set to empty)";
				break;

			case "invalid":
				newKid = (ctx.config.invalidKid as string | undefined) ?? "non-existent-key-id-12345";
				mutation = "Set kid to non-existent key ID";
				break;

			case "injection": {
				// Path traversal / injection payloads
				const defaultPayload = "../../../../../../etc/passwd";
				newKid = (ctx.config.injectionPayload as string | undefined) ?? defaultPayload;
				mutation = "Set kid to injection payload";
				break;
			}

			case "sql": {
				// SQL injection payloads (some implementations query DB for keys)
				const defaultSqlPayload = "' OR '1'='1";
				newKid = (ctx.config.sqlPayload as string | undefined) ?? defaultSqlPayload;
				mutation = "Set kid to SQL injection payload";
				break;
			}

			default:
				return {
					applied: false,
					mutation: `Unknown mode: ${mode}`,
					evidence: { mode },
				};
		}

		ctx.token.header.kid = newKid;

		return {
			applied: true,
			mutation,
			evidence: {
				mode,
				originalKid: originalKid ?? null,
				newKid: newKid ?? null,
				attackType: "kid-manipulation",
			},
		};
	},
};
