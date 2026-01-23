/**
 * Temporal Tampering
 *
 * Manipulates token timestamps (exp, nbf, iat) to test if clients
 * properly validate temporal claims.
 *
 * Modes:
 * - expired: Sets exp to 1 hour in the past
 * - future: Sets nbf to 1 hour in the future (not yet valid)
 * - issued-future: Sets iat to 1 hour in the future (issued in future)
 *
 * Spec: RFC 7519 Section 4.1.4 - exp claim validation
 * CWE-613: Insufficient Session Expiration
 */

import type { MischiefPlugin } from "../types.js";

type TemporalMode = "expired" | "future" | "issued-future";

export const temporalTamperingPlugin: MischiefPlugin = {
	id: "temporal-tampering",
	name: "Temporal Tampering",
	severity: "high",
	phase: "token-claims",

	spec: {
		rfc: "RFC 7519 Section 4.1.4",
		cwe: "CWE-613",
		description: "Clients MUST reject tokens with exp in the past or nbf in the future",
	},

	description: "Sets token exp/nbf/iat to invalid times",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const mode = (ctx.config.mode as TemporalMode | undefined) ?? "expired";
		const now = Math.floor(Date.now() / 1000);
		const oneHour = 3600;

		const original = {
			exp: ctx.token.claims.exp,
			nbf: ctx.token.claims.nbf,
			iat: ctx.token.claims.iat,
		};

		let mutation: string;

		switch (mode) {
			case "expired":
				ctx.token.claims.exp = now - oneHour;
				mutation = `Set exp to ${oneHour}s in the past (expired)`;
				break;

			case "future":
				ctx.token.claims.nbf = now + oneHour;
				mutation = `Set nbf to ${oneHour}s in the future (not yet valid)`;
				break;

			case "issued-future":
				ctx.token.claims.iat = now + oneHour;
				mutation = `Set iat to ${oneHour}s in the future (issued in future)`;
				break;

			default:
				return {
					applied: false,
					mutation: `Unknown mode: ${mode}`,
					evidence: { mode },
				};
		}

		return {
			applied: true,
			mutation,
			evidence: {
				mode,
				original,
				mutated: {
					exp: ctx.token.claims.exp,
					nbf: ctx.token.claims.nbf,
					iat: ctx.token.claims.iat,
				},
			},
		};
	},
};
