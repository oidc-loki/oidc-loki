/**
 * Issuer Confusion Attack
 *
 * Changes the issuer (iss) claim to test if clients properly validate
 * that tokens come from the expected identity provider.
 *
 * Real-world impact: Auth0 multi-tenant bypass (2020)
 *
 * Modes:
 * - evil: Changes issuer to an attacker-controlled URL
 * - similar: Changes issuer to a typosquatting variant
 * - empty: Removes the issuer claim entirely
 * - null: Sets issuer to null
 *
 * Spec: RFC 7519 Section 4.1.1 - iss claim MUST match expected issuer
 * OIDC: OpenID Connect Core 1.0 Section 3.1.3.7 - iss MUST exactly match
 * CWE-290: Authentication Bypass by Spoofing
 */

import type { MischiefPlugin } from "../types.js";

type IssuerMode = "evil" | "similar" | "empty" | "null";

export const issuerConfusionPlugin: MischiefPlugin = {
	id: "issuer-confusion",
	name: "Issuer Confusion",
	severity: "critical",
	phase: "token-claims",

	spec: {
		rfc: "RFC 7519 Section 4.1.1",
		oidc: "OIDC Core 1.0 Section 3.1.3.7",
		cwe: "CWE-290",
		description: "The 'iss' claim MUST exactly match the expected issuer identifier",
	},

	description: "Spoofs the issuer claim to test iss validation",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const mode = (ctx.config.mode as IssuerMode | undefined) ?? "evil";
		const originalIss = ctx.token.claims.iss;

		let newIss: string | null | undefined;
		let mutation: string;

		switch (mode) {
			case "evil":
				newIss = (ctx.config.evilIssuer as string | undefined) ?? "https://evil-idp.attacker.com";
				mutation = "Spoofed issuer to attacker-controlled URL";
				break;

			case "similar": {
				// Create a typosquatting variant
				if (originalIss) {
					newIss = originalIss.replace("https://", "https://auth.").replace(".com", ".co");
				} else {
					newIss = "https://similar-issuer.co";
				}
				mutation = "Changed issuer to typosquatting variant";
				break;
			}

			case "empty":
				newIss = "";
				mutation = "Set issuer to empty string";
				break;

			case "null":
				newIss = null as unknown as string;
				mutation = "Set issuer to null";
				break;

			default:
				return {
					applied: false,
					mutation: `Unknown mode: ${mode}`,
					evidence: { mode },
				};
		}

		ctx.token.claims.iss = newIss as string;

		return {
			applied: true,
			mutation,
			evidence: {
				mode,
				originalIssuer: originalIss,
				spoofedIssuer: newIss,
				attackType: "issuer-confusion",
			},
		};
	},
};
