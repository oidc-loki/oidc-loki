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

		const unicodeTricks = [
			{
				name: "homoglyph-sub",
				apply: () => {
					const sub = String(ctx.token!.claims.sub || "user");
					ctx.token!.claims.sub = sub.replace(/a/g, "\u0430");
				},
			},
			{
				name: "zero-width-injection",
				apply: () => {
					const sub = String(ctx.token!.claims.sub || "user");
					ctx.token!.claims.sub = `${sub}\u200B\u200C\u200D`;
				},
			},
			{
				name: "nfkc-bypass",
				apply: () => {
					ctx.token!.claims.sub = "admin\uFB01le";
				},
			},
			{
				name: "case-folding",
				apply: () => {
					ctx.token!.claims.sub = "ADM\u0131N";
				},
			},
		];

		const idx = Math.floor(Math.random() * unicodeTricks.length);
		const selectedTrick = unicodeTricks[idx]!;
		const originalSub = ctx.token.claims.sub;
		selectedTrick.apply();

		return {
			applied: true,
			mutation: `Applied Unicode trick: ${selectedTrick.name}`,
			evidence: {
				trickType: selectedTrick.name,
				originalSub,
				newSub: ctx.token.claims.sub,
				vulnerability: "Client should normalize Unicode before string comparison",
			},
		};
	},
};
