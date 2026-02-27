/**
 * Response classification layer.
 *
 * Shared logic for distinguishing between different categories of AS
 * responses so that verify() functions don't treat all 4xx as "pass."
 *
 * Categories:
 *   - success:            2xx with expected body
 *   - security_rejection: 400/403 with grant-related error codes
 *   - auth_error:         401 or client-authentication failure
 *   - rate_limit:         429
 *   - server_error:       5xx
 *   - unknown:            anything else
 */

import type { AttackResponse } from "./types.js";

export type ResponseCategory =
	| "success"
	| "security_rejection"
	| "auth_error"
	| "rate_limit"
	| "server_error"
	| "unsupported"
	| "unknown";

/** OAuth error codes that indicate a security-relevant rejection */
const SECURITY_REJECTION_ERRORS = new Set([
	"invalid_grant",
	"invalid_target",
	"invalid_request",
	"invalid_scope",
	"unauthorized_client",
	"access_denied",
]);

/** OAuth error codes that indicate client auth failure (not security rejection) */
const AUTH_ERROR_CODES = new Set(["invalid_client"]);

/**
 * OAuth error codes that indicate the AS does not support the requested feature.
 * These are inconclusive — the AS can't be tested for a feature it doesn't support.
 */
const UNSUPPORTED_ERRORS = new Set(["unsupported_grant_type", "unsupported_response_type"]);

export function classifyResponse(response: AttackResponse): ResponseCategory {
	if (response.status >= 200 && response.status < 300) {
		return "success";
	}

	if (response.status === 429) {
		return "rate_limit";
	}

	if (response.status >= 500) {
		return "server_error";
	}

	if (response.status === 401) {
		return "auth_error";
	}

	if (response.status === 400 || response.status === 403) {
		return classifyByErrorCode(response);
	}

	return "unknown";
}

/** Classify 400/403 responses by inspecting the OAuth error code */
function classifyByErrorCode(response: AttackResponse): ResponseCategory {
	const errorCode = extractErrorCode(response);
	if (errorCode && AUTH_ERROR_CODES.has(errorCode)) {
		return "auth_error";
	}
	if (errorCode && UNSUPPORTED_ERRORS.has(errorCode)) {
		return "unsupported";
	}
	if (errorCode && SECURITY_REJECTION_ERRORS.has(errorCode)) {
		return "security_rejection";
	}
	// 400/403 without recognizable error code — assume security rejection
	// (the AS may not follow the standard error format)
	return "security_rejection";
}

/**
 * Check if a response is a security rejection (the AS deliberately
 * rejected the request for policy/validation reasons).
 *
 * This is the primary check used in attack test verify() functions —
 * it returns true only for genuine security rejections, not auth errors,
 * rate limits, or server errors.
 */
export function isSecurityRejection(response: AttackResponse): boolean {
	return classifyResponse(response) === "security_rejection";
}

/**
 * Check if a response indicates the test result is inconclusive due to
 * infrastructure issues (auth errors, rate limits, server errors).
 */
export function isInconclusive(response: AttackResponse): boolean {
	const category = classifyResponse(response);
	return (
		category === "auth_error" ||
		category === "rate_limit" ||
		category === "server_error" ||
		category === "unsupported" ||
		category === "unknown"
	);
}

/**
 * Safely extract a JSON body from an AttackResponse.
 * Returns undefined if the body is not an object.
 */
export function jsonBody(response: AttackResponse): Record<string, unknown> | undefined {
	if (
		response.body !== null &&
		typeof response.body === "object" &&
		!Array.isArray(response.body)
	) {
		return response.body as Record<string, unknown>;
	}
	return undefined;
}

/**
 * Extract a JSON body from an AttackResponse, throwing if not an object.
 * Use in attack/setup phases where a JSON body is required.
 */
export function requireJsonBody(response: AttackResponse): Record<string, unknown> {
	const body = jsonBody(response);
	if (!body) {
		throw new Error(
			`Expected JSON object body but got ${typeof response.body}: ${String(response.body).slice(0, 100)}`,
		);
	}
	return body;
}

/**
 * Format a human-readable description of the response classification
 * for use in verdict reasons.
 */
export function describeResponse(response: AttackResponse): string {
	const category = classifyResponse(response);
	const errorCode = extractErrorCode(response);
	const suffix = errorCode ? ` (${errorCode})` : "";

	switch (category) {
		case "success":
			return `HTTP ${response.status} success`;
		case "security_rejection":
			return `HTTP ${response.status} security rejection${suffix}`;
		case "auth_error":
			return `HTTP ${response.status} auth error${suffix}`;
		case "rate_limit":
			return `HTTP ${response.status} rate limited`;
		case "server_error":
			return `HTTP ${response.status} server error`;
		case "unsupported":
			return `HTTP ${response.status} unsupported${suffix}`;
		default:
			return `HTTP ${response.status}${suffix}`;
	}
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

function extractErrorCode(response: AttackResponse): string | undefined {
	if (response.body !== null && typeof response.body === "object") {
		const body = response.body as Record<string, unknown>;
		if (typeof body.error === "string") {
			return body.error;
		}
	}
	return undefined;
}
