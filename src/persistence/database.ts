/**
 * SQLite Database - persistence layer for sessions and ledger entries
 *
 * Uses better-sqlite3 for synchronous, fast SQLite operations.
 * Schema follows the architecture design for session and ledger storage.
 */

import Database from "better-sqlite3";
import type { Session } from "../core/types.js";
import type { LedgerEntry } from "../ledger/types.js";

export interface DatabaseConfig {
	path: string;
	verbose?: boolean;
}

/**
 * Loki Database - manages SQLite persistence
 */
export class LokiDatabase {
	private readonly db: Database.Database;

	constructor(config: DatabaseConfig) {
		this.db = new Database(config.path, {
			verbose: config.verbose ? console.log : undefined,
		});

		// Enable WAL mode for better concurrent access
		this.db.pragma("journal_mode = WAL");

		// Run migrations
		this.migrate();
	}

	/**
	 * Run database migrations
	 */
	private migrate(): void {
		// Sessions table
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS sessions (
				id TEXT PRIMARY KEY,
				name TEXT,
				mode TEXT NOT NULL,
				mischief TEXT NOT NULL,  -- JSON array of plugin IDs
				probability REAL,
				shuffle_queue TEXT,      -- JSON array for shuffled mode
				started_at TEXT NOT NULL,
				ended_at TEXT,
				created_at TEXT DEFAULT CURRENT_TIMESTAMP
			)
		`);

		// Ledger entries table
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS ledger_entries (
				id TEXT PRIMARY KEY,
				session_id TEXT NOT NULL,
				request_id TEXT NOT NULL,
				timestamp TEXT NOT NULL,
				plugin_id TEXT NOT NULL,
				plugin_name TEXT NOT NULL,
				plugin_severity TEXT NOT NULL,
				spec_rfc TEXT,
				spec_oidc TEXT,
				spec_cwe TEXT,
				spec_requirement TEXT NOT NULL,
				spec_violation TEXT NOT NULL,
				evidence TEXT NOT NULL,  -- JSON object
				created_at TEXT DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
			)
		`);

		// Index for session lookups
		this.db.exec(`
			CREATE INDEX IF NOT EXISTS idx_ledger_session
			ON ledger_entries(session_id)
		`);

		// Index for request lookups
		this.db.exec(`
			CREATE INDEX IF NOT EXISTS idx_ledger_request
			ON ledger_entries(request_id)
		`);
	}

	/**
	 * Save a session to the database
	 */
	saveSession(session: Session): void {
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO sessions
			(id, name, mode, mischief, probability, shuffle_queue, started_at, ended_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`);

		stmt.run(
			session.id,
			session.name ?? null,
			session.mode,
			JSON.stringify(session.mischief),
			session.probability ?? null,
			session.shuffleQueue ? JSON.stringify(session.shuffleQueue) : null,
			session.startedAt.toISOString(),
			session.endedAt?.toISOString() ?? null,
		);
	}

	/**
	 * Load a session from the database
	 */
	loadSession(id: string): Session | undefined {
		const stmt = this.db.prepare(`
			SELECT * FROM sessions WHERE id = ?
		`);

		const row = stmt.get(id) as SessionRow | undefined;
		if (!row) return undefined;

		return this.rowToSession(row);
	}

	/**
	 * Load all sessions from the database
	 */
	loadAllSessions(): Session[] {
		const stmt = this.db.prepare(`
			SELECT * FROM sessions ORDER BY started_at DESC
		`);

		const rows = stmt.all() as SessionRow[];
		return rows.map((row) => this.rowToSession(row));
	}

	/**
	 * Delete a session and its ledger entries
	 */
	deleteSession(id: string): boolean {
		const stmt = this.db.prepare("DELETE FROM sessions WHERE id = ?");
		const result = stmt.run(id);
		return result.changes > 0;
	}

	/**
	 * Purge all sessions and ledger entries
	 */
	purgeAll(): void {
		this.db.exec("DELETE FROM ledger_entries");
		this.db.exec("DELETE FROM sessions");
	}

	/**
	 * Save a ledger entry
	 */
	saveLedgerEntry(sessionId: string, entry: LedgerEntry): void {
		const stmt = this.db.prepare(`
			INSERT INTO ledger_entries
			(id, session_id, request_id, timestamp, plugin_id, plugin_name,
			 plugin_severity, spec_rfc, spec_oidc, spec_cwe, spec_requirement,
			 spec_violation, evidence)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`);

		stmt.run(
			entry.id,
			sessionId,
			entry.requestId,
			entry.timestamp,
			entry.plugin.id,
			entry.plugin.name,
			entry.plugin.severity,
			entry.spec.rfc ?? null,
			entry.spec.oidc ?? null,
			entry.spec.cwe ?? null,
			entry.spec.requirement,
			entry.spec.violation,
			JSON.stringify(entry.evidence),
		);
	}

	/**
	 * Load ledger entries for a session
	 */
	loadLedgerEntries(sessionId: string): LedgerEntry[] {
		const stmt = this.db.prepare(`
			SELECT * FROM ledger_entries
			WHERE session_id = ?
			ORDER BY timestamp ASC
		`);

		const rows = stmt.all(sessionId) as LedgerEntryRow[];
		return rows.map((row) => this.rowToLedgerEntry(row));
	}

	/**
	 * Close the database connection
	 */
	close(): void {
		this.db.close();
	}

	/**
	 * Convert a database row to a Session object
	 */
	private rowToSession(row: SessionRow): Session {
		const session: Session = {
			id: row.id,
			mode: row.mode as Session["mode"],
			mischief: JSON.parse(row.mischief) as string[],
			startedAt: new Date(row.started_at),
		};

		if (row.name) session.name = row.name;
		if (row.probability !== null) session.probability = row.probability;
		if (row.shuffle_queue) session.shuffleQueue = JSON.parse(row.shuffle_queue) as string[];
		if (row.ended_at) session.endedAt = new Date(row.ended_at);

		return session;
	}

	/**
	 * Convert a database row to a LedgerEntry object
	 */
	private rowToLedgerEntry(row: LedgerEntryRow): LedgerEntry {
		const entry: LedgerEntry = {
			id: row.id,
			requestId: row.request_id,
			timestamp: row.timestamp,
			plugin: {
				id: row.plugin_id,
				name: row.plugin_name,
				severity: row.plugin_severity as LedgerEntry["plugin"]["severity"],
			},
			spec: {
				requirement: row.spec_requirement,
				violation: row.spec_violation,
			},
			evidence: JSON.parse(row.evidence) as Record<string, unknown>,
		};

		if (row.spec_rfc) entry.spec.rfc = row.spec_rfc;
		if (row.spec_oidc) entry.spec.oidc = row.spec_oidc;
		if (row.spec_cwe) entry.spec.cwe = row.spec_cwe;

		return entry;
	}
}

/** Database row types */
interface SessionRow {
	id: string;
	name: string | null;
	mode: string;
	mischief: string;
	probability: number | null;
	shuffle_queue: string | null;
	started_at: string;
	ended_at: string | null;
}

interface LedgerEntryRow {
	id: string;
	session_id: string;
	request_id: string;
	timestamp: string;
	plugin_id: string;
	plugin_name: string;
	plugin_severity: string;
	spec_rfc: string | null;
	spec_oidc: string | null;
	spec_cwe: string | null;
	spec_requirement: string;
	spec_violation: string;
	evidence: string;
}
