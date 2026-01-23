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

		const attacks = [
			{
				name: "add-code-claim",
				apply: () => {
					ctx.token!.claims.code = "injected-auth-code";
				},
			},
			{
				name: "add-implicit-claims",
				apply: () => {
					ctx.token!.claims.token_type = "Bearer";
					ctx.token!.claims.implicit_flow = true;
				},
			},
			{
				name: "hybrid-confusion",
				apply: () => {
					ctx.token!.claims.code = "fake-code";
					ctx.token!.claims.access_token_hash = "fake-hash";
				},
			},
		];

		const idx = Math.floor(Math.random() * attacks.length);
		const selectedAttack = attacks[idx]!;
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
