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

		const scenarios = [
			{
				name: "missing-exp",
				apply: () => {
					delete ctx.token!.claims.exp;
				},
			},
			{
				name: "missing-iat",
				apply: () => {
					delete ctx.token!.claims.iat;
				},
			},
			{
				name: "empty-sub",
				apply: () => {
					ctx.token!.claims.sub = "";
				},
			},
			{
				name: "null-iss",
				apply: () => {
					ctx.token!.claims.iss = null as unknown as string;
				},
			},
		];

		const idx = Math.floor(Math.random() * scenarios.length);
		const selectedScenario = scenarios[idx]!;
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
