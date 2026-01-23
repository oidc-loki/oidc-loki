import type { MischiefPlugin } from "../types.js";

export const claimTypeCoercion: MischiefPlugin = {
	id: "claim-type-coercion",
	name: "Claim Type Coercion",
	severity: "medium",
	phase: "token-claims",
	spec: {
		description: "Changes claim types to test type validation",
		rfc: "RFC 7519 Section 4",
		cwe: "CWE-843",
	},
	description: "Coerces claim types (string to array, number to string, etc.)",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const token = ctx.token;
		const coercions = [
			{
				name: "sub-to-array",
				apply: () => {
					const sub = token.claims.sub;
					token.claims.sub = [sub, "admin"] as unknown as string;
				},
			},
			{
				name: "aud-to-object",
				apply: () => {
					token.claims.aud = {
						primary: token.claims.aud,
						admin: true,
					} as unknown as string;
				},
			},
			{
				name: "exp-to-string",
				apply: () => {
					token.claims.exp = "never" as unknown as number;
				},
			},
			{
				name: "iat-to-string",
				apply: () => {
					token.claims.iat = "beginning-of-time" as unknown as number;
				},
			},
		];

		const selectedCoercion = coercions[
			Math.floor(Math.random() * coercions.length)
		] as (typeof coercions)[0];
		selectedCoercion.apply();

		return {
			applied: true,
			mutation: `Applied type coercion: ${selectedCoercion.name}`,
			evidence: {
				coercionType: selectedCoercion.name,
				vulnerability: "Client should validate claim types match expected format",
			},
		};
	},
};
