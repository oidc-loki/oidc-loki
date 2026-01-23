import type { MischiefPlugin } from "../types.js";

export const errorInjection: MischiefPlugin = {
	id: "error-injection",
	name: "Error Response Injection",
	severity: "medium",
	phase: "token-claims",
	spec: {
		description: "Injects error-like claims to test error handling",
		rfc: "RFC 6749 Section 4.1.2.1",
		cwe: "CWE-209",
	},
	description: "Adds error claims with injection payloads",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const errorPayloads = [
			{
				name: "xss-in-claim",
				error: "invalid_request",
				description: "<script>alert('xss')</script>",
			},
			{
				name: "sql-in-claim",
				error: "invalid_request",
				description: "'; DROP TABLE users; --",
			},
			{
				name: "path-traversal",
				error: "invalid_request",
				description: "../../../etc/passwd",
			},
		];

		const idx = Math.floor(Math.random() * errorPayloads.length);
		const selectedPayload = errorPayloads[idx]!;

		ctx.token.claims.error = selectedPayload.error;
		ctx.token.claims.error_description = selectedPayload.description;

		return {
			applied: true,
			mutation: `Injected ${selectedPayload.name} error payload`,
			evidence: {
				payloadType: selectedPayload.name,
				error: selectedPayload.error,
				errorDescription: selectedPayload.description,
				vulnerability: "Client should sanitize error messages before display",
			},
		};
	},
};
