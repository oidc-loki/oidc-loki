/**
 * Mischief Plugin types
 */

import type { MischiefPhase, Session, Severity } from "../core/types.js";

export interface MischiefPlugin {
	/** Unique identifier, e.g., "alg-none" */
	id: string;

	/** Human-readable name */
	name: string;

	/** RFC/spec reference for the violation */
	spec: SpecReference;

	/** Severity: how bad is it if a client accepts this? */
	severity: Severity;

	/** What this plugin does (for reports) */
	description: string;

	/** Which phase of the OIDC flow this intercepts */
	phase: MischiefPhase;

	/** The actual mischief logic */
	apply(context: MischiefContext): Promise<MischiefResult>;
}

export interface SpecReference {
	/** RFC reference, e.g., "RFC 8725 Section 3.1" */
	rfc?: string;
	/** OIDC Core reference, e.g., "OIDC Core 1.0 Section 3.1.3.7" */
	oidc?: string;
	/** CWE identifier, e.g., "CWE-347" */
	cwe?: string;
	/** Human-readable description of what the spec requires */
	description: string;
}

export interface MischiefContext {
	/** JWT being forged (for token-signing and token-claims phases) */
	token?: TokenContext;
	/** HTTP response being sent (for response phase) */
	response?: ResponseContext;
	/** Plugin-specific configuration */
	config: PluginConfig;
	/** Current test session */
	session: SessionInfo;
}

export interface TokenContext {
	/** JWT header */
	header: JWTHeader;
	/** JWT claims/payload */
	claims: JWTClaims;
	/** Get the current public key (for key confusion attacks) */
	getPublicKey(): Promise<string>;
	/** Sign the token with a specific algorithm and key */
	sign(alg: string, key: string | Buffer): void;
	/** Get the current signature */
	signature: string;
}

export interface JWTHeader {
	alg: string;
	typ?: string;
	kid?: string;
	[key: string]: unknown;
}

export interface JWTClaims {
	iss?: string;
	sub?: string;
	aud?: string | string[];
	exp?: number;
	nbf?: number;
	iat?: number;
	jti?: string;
	[key: string]: unknown;
}

export interface ResponseContext {
	/** HTTP status code */
	status: number;
	/** Response headers */
	headers: Record<string, string>;
	/** Response body (may be modified) */
	body: unknown;
	/** Delay the response by specified milliseconds */
	delay(ms: number): Promise<void>;
}

export type PluginConfig = Record<string, unknown>;

export interface SessionInfo {
	id: string;
	name?: string;
	mode: Session["mode"];
}

export interface MischiefResult {
	/** Whether mischief was actually applied */
	applied: boolean;
	/** Human-readable description of what changed */
	mutation: string;
	/** Evidence for the ledger */
	evidence: Record<string, unknown>;
}
