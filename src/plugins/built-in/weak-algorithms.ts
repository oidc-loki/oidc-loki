import type { MischiefPlugin } from "../types.js";

export const weakAlgorithms: MischiefPlugin = {
	id: "weak-algorithms",
	name: "Weak Algorithm Injection",
	severity: "critical",
	phase: "token-signing",
	spec: {
		description: "Signs tokens with weak algorithms that should be rejected",
		rfc: "RFC 8725 Section 3.1",
		cwe: "CWE-327",
	},
	description: "Uses weak or deprecated signing algorithms that compliant clients should reject",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const weakAlgorithms = ["HS256", "HS384", "HS512"];
		const originalAlg = ctx.token.header.alg;

		const selectedAlg =
			weakAlgorithms[Math.floor(Math.random() * weakAlgorithms.length)] ?? "HS256";
		ctx.token.header.alg = selectedAlg;

		return {
			applied: true,
			mutation: `Changed algorithm from ${originalAlg} to ${selectedAlg}`,
			evidence: {
				originalAlgorithm: originalAlg,
				newAlgorithm: selectedAlg,
				weakness: "Using symmetric algorithm with weak/predictable key",
			},
		};
	},
};
