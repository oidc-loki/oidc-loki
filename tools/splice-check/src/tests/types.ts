/**
 * Core type definitions for splice-check attack tests.
 *
 * Each test follows a three-phase lifecycle:
 *   setup()  → obtain legitimate tokens needed for the attack
 *   attack() → craft and send the malicious token exchange request
 *   verify() → determine whether the AS responded correctly
 */

import type { OAuthClient } from "../client.js";
import type { SpliceCheckConfig } from "../config.js";

// ---------------------------------------------------------------------------
// Test interface
// ---------------------------------------------------------------------------

export interface AttackTest {
	/** Unique identifier, e.g. "basic-splice" */
	id: string;
	/** Human-readable name */
	name: string;
	/** What the test checks */
	description: string;
	/** RFC / spec reference, e.g. "RFC 8693 Section 2.1" */
	spec: string;
	/** Severity if the AS fails this test */
	severity: Severity;

	/** Obtain legitimate tokens needed for this test */
	setup(ctx: TestContext): Promise<SetupResult>;

	/** Craft and send the attack request */
	attack(ctx: TestContext, setup: SetupResult): Promise<AttackResponse>;

	/** Determine if the AS responded correctly */
	verify(response: AttackResponse, setup: SetupResult): TestVerdict;
}

// ---------------------------------------------------------------------------
// Context passed to each test phase
// ---------------------------------------------------------------------------

export interface TestContext {
	config: SpliceCheckConfig;
	client: OAuthClient;
	log: (msg: string) => void;
}

// ---------------------------------------------------------------------------
// Phase results
// ---------------------------------------------------------------------------

export interface SetupResult {
	/** Named tokens obtained during setup */
	tokens: Record<string, string>;
	/** Arbitrary metadata the test wants to pass to attack/verify */
	metadata?: Record<string, unknown>;
}

export interface AttackResponse {
	/** HTTP status code */
	status: number;
	/** Parsed response body (JSON or raw string) */
	body: unknown;
	/** Response headers (lower-cased keys) */
	headers: Record<string, string>;
	/** Round-trip time in milliseconds */
	durationMs: number;
}

export type TestVerdict =
	| { passed: true; reason: string }
	| { passed: false; reason: string; expected: string; actual: string }
	| { skipped: true; reason: string };

// ---------------------------------------------------------------------------
// Shared enums / constants
// ---------------------------------------------------------------------------

export type Severity = "critical" | "high" | "medium" | "low";

/** Standard RFC 8693 token type URIs */
export const TOKEN_TYPE = {
	ACCESS_TOKEN: "urn:ietf:params:oauth:token-type:access_token",
	REFRESH_TOKEN: "urn:ietf:params:oauth:token-type:refresh_token",
	ID_TOKEN: "urn:ietf:params:oauth:token-type:id_token",
	JWT: "urn:ietf:params:oauth:token-type:jwt",
} as const;

/** Standard RFC 8693 grant type */
export const GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
