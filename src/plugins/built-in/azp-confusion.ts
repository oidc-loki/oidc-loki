import type { MischiefPlugin } from "../types.js";

export const azpConfusion: MischiefPlugin = {
	id: "azp-confusion",
	name: "Authorized Party Confusion",
	severity: "high",
	phase: "token-claims",
	spec: {
		description: "Manipulates azp claim to test party validation",
		oidc: "OIDC Core Section 2",
		cwe: "CWE-284",
	},
	description: "Sets azp to different client to test cross-client token acceptance",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const originalAzp = ctx.token.claims.azp;
		const originalAud = ctx.token.claims.aud;

		const attackerClients = [
			"attacker-client",
			"admin-client",
			"privileged-service",
			"internal-api",
		];

		const idx = Math.floor(Math.random() * attackerClients.length);
		const selectedClient = attackerClients[idx]!;

		ctx.token.claims.azp = selectedClient;

		if (Array.isArray(originalAud)) {
			const audArray: string[] = originalAud.filter((a): a is string => typeof a === "string");
			ctx.token.claims.aud = [...audArray, selectedClient];
		} else if (typeof originalAud === "string") {
			ctx.token.claims.aud = [originalAud, selectedClient];
		} else {
			ctx.token.claims.aud = selectedClient;
		}

		return {
			applied: true,
			mutation: `Changed azp to ${selectedClient}`,
			evidence: {
				originalAzp,
				newAzp: selectedClient,
				originalAud,
				newAud: ctx.token.claims.aud,
				vulnerability: "Token authorized for different client",
			},
		};
	},
};
