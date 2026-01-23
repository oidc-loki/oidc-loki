import type { MischiefPlugin } from "../types.js";

export const issInResponseAttack: MischiefPlugin = {
	id: "iss-in-response-attack",
	name: "Issuer in Authorization Response",
	severity: "critical",
	phase: "token-claims",
	spec: {
		description: "Tests RFC 9207 iss parameter validation",
		rfc: "RFC 9207",
		cwe: "CWE-290",
	},
	description: "Manipulates issuer to test iss parameter validation",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const attacks = [
			{ type: "mismatch", issuer: "https://evil-issuer.com" },
			{ type: "similar", issuer: "https://www.legitimate-issuer.com" },
			{ type: "subdomain", issuer: "https://issuer.attacker.com" },
		];

		const selectedAttack = attacks[Math.floor(Math.random() * attacks.length)] ?? attacks[0];
		const originalIss = ctx.token.claims.iss;
		ctx.token.claims.iss = selectedAttack.issuer;

		return {
			applied: true,
			mutation: `Applied ${selectedAttack.type} attack on iss claim`,
			evidence: {
				attackType: selectedAttack.type,
				originalIss,
				newIss: ctx.token.claims.iss,
				vulnerability: "Client must validate iss matches expected issuer",
			},
		};
	},
};
