import type { MischiefPlugin } from "../types.js";

export const responseTypeConfusion: MischiefPlugin = {
	id: "response-type-confusion",
	name: "Response Type Confusion",
	severity: "high",
	phase: "token-claims",
	spec: {
		description: "Adds unexpected claims for response type confusion",
		oidc: "OIDC Core Section 3",
		cwe: "CWE-287",
	},
	description: "Adds claims that shouldn't be present for the response type",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const token = ctx.token;
		const attacks = [
			{
				name: "add-code-claim",
				apply: () => {
					token.claims.code = "injected-auth-code";
				},
			},
			{
				name: "add-implicit-claims",
				apply: () => {
					token.claims.token_type = "Bearer";
					token.claims.implicit_flow = true;
				},
			},
			{
				name: "hybrid-confusion",
				apply: () => {
					token.claims.code = "fake-code";
					token.claims.access_token_hash = "fake-hash";
				},
			},
		];

		const selectedAttack = attacks[Math.floor(Math.random() * attacks.length)] ?? attacks[0];
		selectedAttack.apply();

		return {
			applied: true,
			mutation: `Applied ${selectedAttack.name} attack`,
			evidence: {
				attackName: selectedAttack.name,
				vulnerability: "Client should reject unexpected response parameters",
			},
		};
	},
};
