import type { MischiefPlugin } from "../types.js";

export const atHashCHashMismatch: MischiefPlugin = {
	id: "at-hash-c-hash-mismatch",
	name: "Token Hash Mismatch",
	severity: "high",
	phase: "token-claims",
	spec: {
		description: "Creates mismatched at_hash and c_hash values",
		oidc: "OIDC Core Section 3.1.3.6",
		cwe: "CWE-354",
	},
	description: "Injects incorrect hash values to test hash validation",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const originalAtHash = ctx.token.claims.at_hash;
		const originalCHash = ctx.token.claims.c_hash;

		const fakeHash = "AAAAAAAAAAAAAAAAAAAAAA";
		const mutations: string[] = [];

		if (originalAtHash !== undefined || Math.random() > 0.5) {
			ctx.token.claims.at_hash = fakeHash;
			mutations.push("at_hash");
		}

		if (originalCHash !== undefined || Math.random() > 0.5) {
			ctx.token.claims.c_hash = fakeHash;
			mutations.push("c_hash");
		}

		if (mutations.length === 0) {
			ctx.token.claims.at_hash = fakeHash;
			mutations.push("at_hash");
		}

		return {
			applied: true,
			mutation: `Injected invalid ${mutations.join(" and ")}`,
			evidence: {
				originalAtHash,
				originalCHash,
				injectedHash: fakeHash,
				modifiedClaims: mutations,
				vulnerability: "Client should verify hashes match the actual access_token/code",
			},
		};
	},
};
