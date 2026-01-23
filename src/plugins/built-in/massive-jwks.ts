import type { MischiefPlugin } from "../types.js";

export const massiveJwks: MischiefPlugin = {
	id: "massive-jwks",
	name: "Massive JWKS Response",
	severity: "medium",
	phase: "token-claims",
	spec: {
		description: "References JWKS with thousands of keys",
		rfc: "RFC 7517",
		cwe: "CWE-400",
	},
	description: "Tests client handling of oversized JWKS responses",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const keyCounts = [100, 1000, 10000];
		const selectedCount = keyCounts[Math.floor(Math.random() * keyCounts.length)] ?? 100;

		// Add a header indicating massive JWKS
		ctx.token.header.kid = `key-among-${selectedCount}`;
		ctx.token.claims.jwks_key_count = selectedCount;

		return {
			applied: true,
			mutation: `Token references JWKS with ${selectedCount} keys`,
			evidence: {
				injectedKeyCount: selectedCount,
				kid: ctx.token.header.kid,
			},
		};
	},
};
