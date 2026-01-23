import type { MischiefPlugin } from "../types.js";

export const tokenLifetimeAbuse: MischiefPlugin = {
	id: "token-lifetime-abuse",
	name: "Token Lifetime Abuse",
	severity: "high",
	phase: "token-claims",
	spec: {
		description: "Issues tokens with excessively long lifetimes",
		rfc: "RFC 7519 Section 4.1.4",
		cwe: "CWE-613",
	},
	description: "Creates tokens valid for months or years to test lifetime enforcement",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const now = Math.floor(Date.now() / 1000);
		const originalExp = ctx.token.claims.exp;

		const lifetimes = [
			{ name: "1 year", seconds: 365 * 24 * 60 * 60 },
			{ name: "5 years", seconds: 5 * 365 * 24 * 60 * 60 },
			{ name: "10 years", seconds: 10 * 365 * 24 * 60 * 60 },
			{ name: "100 years", seconds: 100 * 365 * 24 * 60 * 60 },
		];

		const selected = lifetimes[
			Math.floor(Math.random() * lifetimes.length)
		] as (typeof lifetimes)[0];
		ctx.token.claims.exp = now + selected.seconds;
		ctx.token.claims.iat = now;

		return {
			applied: true,
			mutation: `Set token lifetime to ${selected.name}`,
			evidence: {
				originalExp,
				newExp: ctx.token.claims.exp,
				lifetime: selected.name,
				expiresAt: new Date(ctx.token.claims.exp * 1000).toISOString(),
			},
		};
	},
};
