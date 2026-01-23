import type { MischiefPlugin } from "../types.js";

export const partialSuccess: MischiefPlugin = {
	id: "partial-success",
	name: "Partial Success Response",
	severity: "medium",
	phase: "token-claims",
	spec: {
		description: "Creates tokens with missing or null required claims",
		rfc: "RFC 6749",
		cwe: "CWE-754",
	},
	description: "Tests if client handles incomplete token claims",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const token = ctx.token;
		const scenarios = [
			{
				name: "missing-exp",
				apply: () => {
					token.claims.exp = undefined as unknown as number;
				},
			},
			{
				name: "missing-iat",
				apply: () => {
					token.claims.iat = undefined as unknown as number;
				},
			},
			{
				name: "empty-sub",
				apply: () => {
					token.claims.sub = "";
				},
			},
			{
				name: "null-iss",
				apply: () => {
					token.claims.iss = null as unknown as string;
				},
			},
		];

		const selectedScenario =
			scenarios[Math.floor(Math.random() * scenarios.length)] ?? scenarios[0];
		selectedScenario.apply();

		return {
			applied: true,
			mutation: `Applied ${selectedScenario.name} scenario`,
			evidence: {
				scenario: selectedScenario.name,
				vulnerability: "Client should validate all required claims are present",
			},
		};
	},
};
