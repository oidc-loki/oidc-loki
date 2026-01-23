import type { MischiefPlugin } from "../types.js";

export const unicodeNormalization: MischiefPlugin = {
	id: "unicode-normalization",
	name: "Unicode Normalization Attack",
	severity: "medium",
	phase: "token-claims",
	spec: {
		description: "Uses Unicode tricks to bypass string comparisons",
		rfc: "RFC 7519",
		cwe: "CWE-176",
	},
	description: "Injects Unicode lookalikes and normalization edge cases",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const token = ctx.token;
		const unicodeTricks = [
			{
				name: "homoglyph-sub",
				apply: () => {
					const sub = String(token.claims.sub || "user");
					token.claims.sub = sub.replace(/a/g, "\u0430");
				},
			},
			{
				name: "zero-width-injection",
				apply: () => {
					const sub = String(token.claims.sub || "user");
					token.claims.sub = `${sub}\u200B\u200C\u200D`;
				},
			},
			{
				name: "nfkc-bypass",
				apply: () => {
					token.claims.sub = "admin\uFB01le";
				},
			},
			{
				name: "case-folding",
				apply: () => {
					token.claims.sub = "ADM\u0131N";
				},
			},
		];

		const selectedTrick = unicodeTricks[
			Math.floor(Math.random() * unicodeTricks.length)
		] as (typeof unicodeTricks)[0];
		const originalSub = token.claims.sub;
		selectedTrick.apply();

		return {
			applied: true,
			mutation: `Applied Unicode trick: ${selectedTrick.name}`,
			evidence: {
				trickType: selectedTrick.name,
				originalSub,
				newSub: token.claims.sub,
				vulnerability: "Client should normalize Unicode before string comparison",
			},
		};
	},
};
