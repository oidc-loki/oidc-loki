import type { MischiefPlugin } from "../types.js";

export const jwksDomainMismatch: MischiefPlugin = {
	id: "jwks-domain-mismatch",
	name: "JWKS Domain Mismatch",
	severity: "critical",
	phase: "token-signing",
	spec: {
		description: "Points to JWKS URI on a different domain than the issuer",
		rfc: "RFC 8414 Section 2",
		cwe: "CWE-346",
	},
	description: "Tests if client validates that jwks_uri domain matches issuer domain",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const attackerDomains = [
			"https://evil.com/.well-known/jwks.json",
			"https://attacker.example.com/keys",
			"https://legitimate-looking-idp.com/jwks",
			"https://idp.legitimate.com.attacker.com/jwks",
		];

		const selectedDomain =
			attackerDomains[Math.floor(Math.random() * attackerDomains.length)] ?? attackerDomains[0];

		ctx.token.header.jku = selectedDomain;

		return {
			applied: true,
			mutation: `Injected jku pointing to mismatched domain: ${selectedDomain}`,
			evidence: {
				maliciousJwksUri: selectedDomain,
				vulnerability: "JWKS could be loaded from untrusted domain",
			},
		};
	},
};
