import type { MischiefPlugin } from "../types.js";

export const responseModeMismatch: MischiefPlugin = {
	id: "response-mode-mismatch",
	name: "Response Mode Mismatch",
	severity: "medium",
	phase: "token-claims",
	spec: {
		description: "Adds claims indicating response mode mismatch",
		rfc: "OAuth 2.0 Multiple Response Types",
		cwe: "CWE-233",
	},
	description: "Tests if client handles response mode mismatches securely",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const modes = ["query", "fragment", "form_post"];
		const selectedMode = modes[Math.floor(Math.random() * modes.length)] ?? "query";

		ctx.token.claims.delivered_via = selectedMode;
		ctx.token.claims.expected_mode = "code";

		return {
			applied: true,
			mutation: `Token indicates delivery via ${selectedMode} mode`,
			evidence: {
				deliveryMode: selectedMode,
				vulnerability: "Client should validate response mode matches request",
			},
		};
	},
};
