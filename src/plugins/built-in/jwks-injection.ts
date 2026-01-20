/**
 * JWKS Injection Attack
 *
 * Manipulates the JSON Web Key Set (JWKS) endpoint response to test if clients
 * properly validate keys and handle key confusion scenarios.
 *
 * Real-world impact: Signature bypass, key injection allows signing arbitrary tokens
 *
 * Modes:
 * - inject-key: Adds an attacker-controlled key to the JWKS
 * - empty: Returns an empty JWKS (denial of service/fallback testing)
 * - malformed: Returns malformed JWKS to test error handling
 * - wrong-use: Changes key "use" from "sig" to "enc" or vice versa
 * - weak-key: Injects a weak/small RSA key
 *
 * Spec: RFC 7517 - JSON Web Key (JWK)
 * Spec: RFC 7518 - JSON Web Algorithms (JWA)
 * CWE-327: Use of a Broken or Risky Cryptographic Algorithm
 * CWE-347: Improper Verification of Cryptographic Signature
 */

import type { MischiefPlugin } from "../types.js";

type JwksMode = "inject-key" | "empty" | "malformed" | "wrong-use" | "weak-key";

export interface JWK {
	kty: string;
	use?: string;
	key_ops?: string[];
	alg?: string;
	kid?: string;
	x5u?: string;
	x5c?: string[];
	x5t?: string;
	"x5t#S256"?: string;
	// RSA keys
	n?: string;
	e?: string;
	// EC keys
	crv?: string;
	x?: string;
	y?: string;
	// Symmetric keys
	k?: string;
	[key: string]: unknown;
}

export interface JWKS {
	keys: JWK[];
}

export const jwksInjectionPlugin: MischiefPlugin = {
	id: "jwks-injection",
	name: "JWKS Injection",
	severity: "critical",
	phase: "discovery",

	spec: {
		rfc: "RFC 7517, RFC 7518",
		cwe: "CWE-347",
		description: "JWKS keys MUST be validated and matched correctly to token signatures",
	},

	description: "Manipulates JWKS response to test key validation",

	async apply(ctx) {
		// JWKS plugins receive the JWKS in response.body
		if (!ctx.response?.body) {
			return { applied: false, mutation: "No JWKS context", evidence: {} };
		}

		const mode = (ctx.config.mode as JwksMode | undefined) ?? "inject-key";
		const jwks = ctx.response.body as JWKS;
		const originalKeyCount = jwks.keys?.length ?? 0;

		let mutation: string;
		const evidence: Record<string, unknown> = { mode, originalKeyCount };

		switch (mode) {
			case "inject-key": {
				// Inject an attacker-controlled key
				// This is a small RSA key that attacker controls
				const attackerKey: JWK = (ctx.config.attackerKey as JWK | undefined) ?? {
					kty: "RSA",
					use: "sig",
					alg: "RS256",
					kid: "attacker-key-001",
					// This is a small 512-bit RSA key for demonstration
					// In real attacks, the attacker would have the private key
					n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
					e: "AQAB",
				};

				if (!jwks.keys) {
					jwks.keys = [];
				}
				jwks.keys.push(attackerKey);
				mutation = `Injected attacker-controlled key with kid '${attackerKey.kid}'`;
				evidence.injectedKid = attackerKey.kid;
				evidence.newKeyCount = jwks.keys.length;
				break;
			}

			case "empty": {
				// Return empty JWKS (tests fallback behavior)
				jwks.keys = [];
				mutation = "Returned empty JWKS (no keys)";
				evidence.newKeyCount = 0;
				break;
			}

			case "malformed": {
				// Return malformed JWKS to test error handling
				const malformedType = (ctx.config.malformedType as string | undefined) ?? "missing-kty";
				let malformedMutation = "Applied malformed JWKS";

				if (jwks.keys && jwks.keys.length > 0) {
					const key = jwks.keys[0];
					if (key) {
						switch (malformedType) {
							case "missing-kty":
								(key as Record<string, unknown>).kty = undefined;
								malformedMutation = "Removed required 'kty' field from first key";
								break;
							case "invalid-kty":
								key.kty = "INVALID";
								malformedMutation = "Set 'kty' to invalid value";
								break;
							case "missing-n":
								if (key.kty === "RSA") {
									(key as Record<string, unknown>).n = undefined;
									malformedMutation = "Removed required 'n' field from RSA key";
								}
								break;
							default:
								(key as Record<string, unknown>).kty = undefined;
								malformedMutation = "Created malformed key (missing kty)";
						}
					}
				}
				evidence.malformedType = malformedType;
				mutation = malformedMutation;
				break;
			}

			case "wrong-use": {
				// Change key use from sig to enc (or vice versa)
				let useMutation = "Changed key use parameter";
				if (jwks.keys && jwks.keys.length > 0) {
					const key = jwks.keys[0];
					if (key) {
						const originalUse = key.use;
						key.use = key.use === "sig" ? "enc" : "sig";
						useMutation = `Changed key use from '${originalUse ?? "undefined"}' to '${key.use}'`;
						evidence.originalUse = originalUse ?? null;
						evidence.newUse = key.use;
					}
				}
				mutation = useMutation;
				break;
			}

			case "weak-key": {
				// Inject a weak 512-bit RSA key (cryptographically weak)
				const weakKey: JWK = {
					kty: "RSA",
					use: "sig",
					alg: "RS256",
					kid: "weak-key-512bit",
					// 512-bit RSA key (factorizable with modern hardware)
					n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
					e: "AQAB",
				};

				// Replace all keys with the weak key
				jwks.keys = [weakKey];
				mutation = "Replaced all keys with weak 512-bit RSA key";
				evidence.weakKeyKid = weakKey.kid;
				evidence.keyStrength = "512-bit RSA (cryptographically weak)";
				break;
			}

			default:
				return {
					applied: false,
					mutation: `Unknown mode: ${mode}`,
					evidence: { mode },
				};
		}

		// Update the response body
		ctx.response.body = jwks;

		evidence.attackType = "jwks-injection";

		return {
			applied: true,
			mutation,
			evidence,
		};
	},
};
