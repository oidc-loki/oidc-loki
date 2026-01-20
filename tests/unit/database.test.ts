import { existsSync, unlinkSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Session } from "../../src/core/types.js";
import type { LedgerEntry } from "../../src/ledger/types.js";
import { LokiDatabase } from "../../src/persistence/database.js";

describe("LokiDatabase", () => {
	const TEST_DB_PATH = "./test-loki.db";
	let db: LokiDatabase;

	beforeEach(() => {
		// Clean up any existing test database
		if (existsSync(TEST_DB_PATH)) {
			unlinkSync(TEST_DB_PATH);
		}
		if (existsSync(`${TEST_DB_PATH}-wal`)) {
			unlinkSync(`${TEST_DB_PATH}-wal`);
		}
		if (existsSync(`${TEST_DB_PATH}-shm`)) {
			unlinkSync(`${TEST_DB_PATH}-shm`);
		}

		db = new LokiDatabase({ path: TEST_DB_PATH });
	});

	afterEach(() => {
		db.close();

		// Clean up test database
		if (existsSync(TEST_DB_PATH)) {
			unlinkSync(TEST_DB_PATH);
		}
		if (existsSync(`${TEST_DB_PATH}-wal`)) {
			unlinkSync(`${TEST_DB_PATH}-wal`);
		}
		if (existsSync(`${TEST_DB_PATH}-shm`)) {
			unlinkSync(`${TEST_DB_PATH}-shm`);
		}
	});

	describe("sessions", () => {
		it("should save and load a session", () => {
			const session: Session = {
				id: "sess_test123",
				name: "Test Session",
				mode: "explicit",
				mischief: ["alg-none", "key-confusion"],
				startedAt: new Date("2026-01-20T10:00:00Z"),
			};

			db.saveSession(session);
			const loaded = db.loadSession(session.id);

			expect(loaded).toBeDefined();
			expect(loaded?.id).toBe(session.id);
			expect(loaded?.name).toBe(session.name);
			expect(loaded?.mode).toBe(session.mode);
			expect(loaded?.mischief).toEqual(session.mischief);
			expect(loaded?.startedAt.toISOString()).toBe(session.startedAt.toISOString());
		});

		it("should save session with optional fields", () => {
			const session: Session = {
				id: "sess_random123",
				mode: "random",
				mischief: ["alg-none"],
				probability: 0.5,
				startedAt: new Date(),
				endedAt: new Date(),
			};

			db.saveSession(session);
			const loaded = db.loadSession(session.id);

			expect(loaded?.probability).toBe(0.5);
			expect(loaded?.endedAt).toBeDefined();
		});

		it("should save session with shuffle queue", () => {
			const session: Session = {
				id: "sess_shuffled123",
				mode: "shuffled",
				mischief: ["alg-none", "key-confusion", "temporal-tampering"],
				shuffleQueue: ["key-confusion", "alg-none", "temporal-tampering"],
				startedAt: new Date(),
			};

			db.saveSession(session);
			const loaded = db.loadSession(session.id);

			expect(loaded?.shuffleQueue).toEqual(session.shuffleQueue);
		});

		it("should return undefined for non-existent session", () => {
			const loaded = db.loadSession("non-existent");
			expect(loaded).toBeUndefined();
		});

		it("should load all sessions", () => {
			const sessions: Session[] = [
				{ id: "sess_1", mode: "explicit", mischief: [], startedAt: new Date() },
				{ id: "sess_2", mode: "random", mischief: ["alg-none"], startedAt: new Date() },
				{ id: "sess_3", mode: "shuffled", mischief: ["key-confusion"], startedAt: new Date() },
			];

			for (const session of sessions) {
				db.saveSession(session);
			}

			const loaded = db.loadAllSessions();
			expect(loaded).toHaveLength(3);
		});

		it("should delete a session", () => {
			const session: Session = {
				id: "sess_delete",
				mode: "explicit",
				mischief: [],
				startedAt: new Date(),
			};

			db.saveSession(session);
			expect(db.loadSession(session.id)).toBeDefined();

			const deleted = db.deleteSession(session.id);
			expect(deleted).toBe(true);
			expect(db.loadSession(session.id)).toBeUndefined();
		});

		it("should return false when deleting non-existent session", () => {
			const deleted = db.deleteSession("non-existent");
			expect(deleted).toBe(false);
		});
	});

	describe("ledger entries", () => {
		const testSession: Session = {
			id: "sess_ledger_test",
			mode: "explicit",
			mischief: ["alg-none"],
			startedAt: new Date(),
		};

		beforeEach(() => {
			db.saveSession(testSession);
		});

		it("should save and load ledger entries", () => {
			const entry: LedgerEntry = {
				id: "entry_123",
				requestId: "req_abc",
				timestamp: new Date().toISOString(),
				plugin: {
					id: "alg-none",
					name: "Algorithm None Injection",
					severity: "critical",
				},
				spec: {
					rfc: "RFC 8725 Section 3.1",
					cwe: "CWE-327",
					requirement: "Tokens MUST be signed",
					violation: "Changed alg to 'none' and removed signature",
				},
				evidence: {
					originalAlg: "RS256",
					newAlg: "none",
				},
			};

			db.saveLedgerEntry(testSession.id, entry);
			const loaded = db.loadLedgerEntries(testSession.id);

			expect(loaded).toHaveLength(1);
			expect(loaded[0]?.id).toBe(entry.id);
			expect(loaded[0]?.plugin.id).toBe("alg-none");
			expect(loaded[0]?.spec.rfc).toBe("RFC 8725 Section 3.1");
			expect(loaded[0]?.evidence.originalAlg).toBe("RS256");
		});

		it("should load multiple ledger entries in order", () => {
			const entries: LedgerEntry[] = [
				{
					id: "entry_1",
					requestId: "req_1",
					timestamp: "2026-01-20T10:00:00Z",
					plugin: { id: "alg-none", name: "Algorithm None", severity: "critical" },
					spec: { requirement: "Must sign", violation: "Unsigned" },
					evidence: {},
				},
				{
					id: "entry_2",
					requestId: "req_2",
					timestamp: "2026-01-20T10:01:00Z",
					plugin: { id: "key-confusion", name: "Key Confusion", severity: "critical" },
					spec: { requirement: "Must verify", violation: "Wrong alg" },
					evidence: {},
				},
			];

			for (const entry of entries) {
				db.saveLedgerEntry(testSession.id, entry);
			}

			const loaded = db.loadLedgerEntries(testSession.id);
			expect(loaded).toHaveLength(2);
			expect(loaded[0]?.id).toBe("entry_1");
			expect(loaded[1]?.id).toBe("entry_2");
		});

		it("should return empty array for session with no entries", () => {
			const loaded = db.loadLedgerEntries(testSession.id);
			expect(loaded).toEqual([]);
		});
	});

	describe("purge", () => {
		it("should purge all data", () => {
			// Create sessions and entries
			const session: Session = {
				id: "sess_purge_test",
				mode: "explicit",
				mischief: ["alg-none"],
				startedAt: new Date(),
			};
			db.saveSession(session);

			const entry: LedgerEntry = {
				id: "entry_purge",
				requestId: "req_purge",
				timestamp: new Date().toISOString(),
				plugin: { id: "alg-none", name: "Test", severity: "critical" },
				spec: { requirement: "Test", violation: "Test" },
				evidence: {},
			};
			db.saveLedgerEntry(session.id, entry);

			// Verify data exists
			expect(db.loadAllSessions()).toHaveLength(1);
			expect(db.loadLedgerEntries(session.id)).toHaveLength(1);

			// Purge
			db.purgeAll();

			// Verify data is gone
			expect(db.loadAllSessions()).toHaveLength(0);
		});
	});
});
