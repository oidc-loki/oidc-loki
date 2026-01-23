import type { MischiefPlugin } from "../types.js";

export const critHeaderBypass: MischiefPlugin = {
	id: "crit-header-bypass",
	name: "Critical Header Bypass",
	severity: "high",
	phase: "token-signing",
	spec: {
		description: "Adds unknown critical headers that must be understood",
		rfc: "RFC 7515 Section 4.1.11",
		cwe: "CWE-358",
	},
	description: "Includes crit header with unknown extensions to test strict validation",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const unknownHeaders = [
			"x-custom-security",
			"x-bypass-validation",
			"x-admin-override",
			"x-skip-checks",
		];

		ctx.token.header.crit = unknownHeaders;

		for (const header of unknownHeaders) {
			ctx.token.header[header] = true;
		}

		return {
			applied: true,
			mutation: `Added critical headers: ${unknownHeaders.join(", ")}`,
			evidence: {
				criticalHeaders: unknownHeaders,
				vulnerability: "Client must reject tokens with unknown critical headers per RFC 7515",
			},
		};
	},
};
