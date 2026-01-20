/**
 * Audience Confusion Attack
 *
 * Manipulates the audience (aud) claim to test if clients properly validate
 * that tokens are intended for them.
 *
 * Real-world impact: Cross-service token abuse, privilege escalation
 *
 * Modes:
 * - inject: Adds an attacker-controlled audience to the array
 * - replace: Replaces audience with attacker-controlled value
 * - remove: Removes the audience claim entirely
 * - wildcard: Sets audience to "*" (sometimes accepted by misconfigured clients)
 *
 * Spec: RFC 7519 Section 4.1.3 - aud claim MUST match intended recipient
 * OIDC: OpenID Connect Core 1.0 Section 2 - aud MUST contain client_id
 * CWE-284: Improper Access Control
 */

import type { MischiefPlugin } from "../types.js";

type AudienceMode = "inject" | "replace" | "remove" | "wildcard";

export const audienceConfusionPlugin: MischiefPlugin = {
	id: "audience-confusion",
	name: "Audience Confusion",
	severity: "critical",
	phase: "token-claims",

	spec: {
		rfc: "RFC 7519 Section 4.1.3",
		oidc: "OIDC Core 1.0 Section 2",
		cwe: "CWE-284",
		description: "The 'aud' claim MUST identify the intended recipient(s)",
	},

	description: "Manipulates audience claim to test aud validation",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const mode = (ctx.config.mode as AudienceMode | undefined) ?? "inject";
		const originalAud = ctx.token.claims.aud;
		const maliciousAud =
			(ctx.config.maliciousAudience as string | undefined) ?? "https://attacker.com";

		let newAud: string | string[] | undefined;
		let mutation: string;

		switch (mode) {
			case "inject": {
				// Add attacker audience to existing array
				if (Array.isArray(originalAud)) {
					newAud = [...originalAud, maliciousAud];
				} else if (originalAud) {
					newAud = [originalAud, maliciousAud];
				} else {
					newAud = [maliciousAud];
				}
				mutation = `Injected malicious audience '${maliciousAud}'`;
				break;
			}

			case "replace":
				newAud = maliciousAud;
				mutation = `Replaced audience with '${maliciousAud}'`;
				break;

			case "remove":
				newAud = []; // Empty array simulates removal
				mutation = "Removed audience claim (set to empty array)";
				break;

			case "wildcard":
				newAud = "*";
				mutation = `Set audience to wildcard '*'`;
				break;

			default:
				return {
					applied: false,
					mutation: `Unknown mode: ${mode}`,
					evidence: { mode },
				};
		}

		ctx.token.claims.aud = newAud;

		return {
			applied: true,
			mutation,
			evidence: {
				mode,
				originalAudience: originalAud,
				newAudience: newAud ?? null,
				attackType: "audience-confusion",
			},
		};
	},
};
