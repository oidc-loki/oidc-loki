import type { MischiefPlugin } from "../types.js";

export const massiveToken: MischiefPlugin = {
	id: "massive-token",
	name: "Massive Token Payload",
	severity: "medium",
	phase: "token-claims",
	spec: {
		description: "Creates tokens with extremely large payloads",
		rfc: "RFC 7519",
		cwe: "CWE-400",
	},
	description: "Generates oversized tokens to test parsing limits and memory handling",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const sizes = [
			{ name: "100KB", chars: 100 * 1024 },
			{ name: "1MB", chars: 1024 * 1024 },
			{ name: "10MB", chars: 10 * 1024 * 1024 },
		];

		const selected = sizes[Math.floor(Math.random() * sizes.length)] as (typeof sizes)[0];
		const padding = "X".repeat(selected.chars);

		ctx.token.claims.massive_claim = padding;
		ctx.token.claims.nested_data = {
			level1: {
				level2: {
					level3: {
						data: padding.substring(0, 10000),
					},
				},
			},
		};

		return {
			applied: true,
			mutation: `Added ${selected.name} of padding to token claims`,
			evidence: {
				injectedSize: selected.name,
				approximateTokenSize: selected.chars,
				claimsAdded: ["massive_claim", "nested_data"],
			},
		};
	},
};
