import type { MischiefPlugin } from "../types.js";

export const massiveMetadata: MischiefPlugin = {
	id: "massive-metadata",
	name: "Massive Discovery Metadata",
	severity: "medium",
	phase: "token-claims",
	spec: {
		description: "Tests handling of oversized OIDC discovery documents",
		rfc: "RFC 8414",
		cwe: "CWE-400",
	},
	description: "Generates tokens indicating oversized discovery metadata",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const sizes = [
			{ name: "1000 scopes", count: 1000 },
			{ name: "10000 scopes", count: 10000 },
		];

		const selected = sizes[Math.floor(Math.random() * sizes.length)] as (typeof sizes)[0];

		ctx.token.claims.metadata_scope_count = selected.count;

		return {
			applied: true,
			mutation: `Token indicates discovery with ${selected.name}`,
			evidence: {
				injectedScopes: selected.count,
				approximateSize: `${Math.round((selected.count * 150) / 1024)}KB`,
			},
		};
	},
};
