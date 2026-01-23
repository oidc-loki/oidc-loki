/**
 * alg:none injection attack
 *
 * Sets JWT algorithm header to "none" and removes signature.
 * Tests if clients properly validate the algorithm field.
 *
 * Spec: RFC 8725 Section 3.1 - Algorithms MUST NOT include "none"
 * CWE-327: Use of a Broken or Risky Cryptographic Algorithm
 */

import type { MischiefPlugin } from "../types.js";

export const algNonePlugin: MischiefPlugin = {
	id: "alg-none",
	name: "Algorithm None Injection",
	severity: "critical",
	phase: "token-signing",

	spec: {
		rfc: "RFC 8725 Section 3.1",
		cwe: "CWE-327",
		description: "JWTs MUST NOT use 'none' algorithm in production contexts",
	},

	description: "Signs token with alg:none, testing if client validates the algorithm header",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const originalAlg = ctx.token.header.alg;
		ctx.token.header.alg = "none";
		ctx.token.signature = "";

		return {
			applied: true,
			mutation: `Changed alg from '${originalAlg}' to 'none', removed signature`,
			evidence: {
				originalAlg,
				newAlg: "none",
				signatureRemoved: true,
			},
		};
	},
};
