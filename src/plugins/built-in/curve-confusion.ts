import type { MischiefPlugin } from "../types.js";

export const curveConfusion: MischiefPlugin = {
	id: "curve-confusion",
	name: "Elliptic Curve Confusion",
	severity: "critical",
	phase: "token-signing",
	spec: {
		description: "Exploits EC curve validation vulnerabilities",
		rfc: "RFC 7518 Section 3.4",
		cwe: "CWE-327",
	},
	description: "Manipulates EC curve parameters to test curve validation",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const originalAlg = ctx.token.header.alg;

		ctx.token.header.alg = "ES256";
		ctx.token.header.jwk = {
			kty: "EC",
			crv: "P-256K",
			x: "WbbXWPtjqoVqsM3-RWQjps6dGnUd-_5FS4hKlG4BQCE",
			y: "duqnQ7RCLrpT4kd8d8NfCV-Y0x8slqZ7LMnT_e9BGpM",
			kid: "curve-confusion-key",
		};

		return {
			applied: true,
			mutation: `Changed to ES256 with non-standard curve P-256K`,
			evidence: {
				originalAlgorithm: originalAlg,
				newAlgorithm: "ES256",
				injectedCurve: "P-256K",
				vulnerability: "Client may accept tokens signed with weak or invalid curves",
			},
		};
	},
};
