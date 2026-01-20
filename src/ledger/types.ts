/**
 * Mischief Ledger types
 */

import type { SessionMode, Severity } from "../core/types.js";

export interface MischiefLedger {
	meta: LedgerMeta;
	summary: LedgerSummary;
	entries: LedgerEntry[];
}

export interface LedgerMeta {
	version: "1.0.0";
	sessionId: string;
	sessionName?: string;
	mode: SessionMode;
	startedAt: string;
	endedAt?: string;
	lokiVersion: string;
}

export interface LedgerSummary {
	totalRequests: number;
	requestsWithMischief: number;
	mischiefByPlugin: Record<string, number>;
	mischiefBySeverity: Record<Severity, number>;
}

export interface LedgerEntry {
	id: string;
	requestId: string;
	timestamp: string;
	plugin: {
		id: string;
		name: string;
		severity: Severity;
	};
	spec: {
		rfc?: string;
		oidc?: string;
		cwe?: string;
		requirement: string;
		violation: string;
	};
	evidence: {
		mutation: string;
		original?: unknown;
		mutated?: unknown;
	};
	config?: Record<string, unknown>;
}

export interface OutcomeReport {
	requestId: string;
	accepted: boolean;
	error?: string;
	notes?: string;
}
