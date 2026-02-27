/**
 * Shared helpers for attack tests.
 */

import type { SetupResult } from "./types.js";

/**
 * Safely retrieve a named token from setup results.
 * Throws a clear error if the token is missing (should never happen
 * if setup completed successfully).
 */
export function requireToken(setup: SetupResult, name: string): string {
	const token = setup.tokens[name];
	if (!token) {
		throw new Error(`Bug: expected token "${name}" from setup, but it was not found`);
	}
	return token;
}

/**
 * Redact known token values from a log message.
 * Replaces any occurrence of a known token value with [REDACTED:<name>].
 */
export function redactTokens(msg: string, tokens: Record<string, string>): string {
	let result = msg;
	for (const [name, value] of Object.entries(tokens)) {
		if (value.length >= 8) {
			result = result.replaceAll(value, `[REDACTED:${name}]`);
		}
	}
	return result;
}
