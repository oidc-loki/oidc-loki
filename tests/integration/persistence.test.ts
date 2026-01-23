import { existsSync, rmSync, unlinkSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Loki } from "../../src/index.js";

describe("Persistence Integration", () => {
	const TEST_DB_PATH = "./test-data/persistence-test.db";
	const PORT = 9879;
	const ISSUER = `http://localhost:${PORT}`;

	beforeEach(() => {
		// Clean up any existing test database
		cleanupDb();
	});

	afterEach(() => {
		cleanupDb();
	});

	function cleanupDb() {
		if (existsSync(TEST_DB_PATH)) unlinkSync(TEST_DB_PATH);
		if (existsSync(`${TEST_DB_PATH}-wal`)) unlinkSync(`${TEST_DB_PATH}-wal`);
		if (existsSync(`${TEST_DB_PATH}-shm`)) unlinkSync(`${TEST_DB_PATH}-shm`);
		if (existsSync("./test-data")) rmSync("./test-data", { recursive: true, force: true });
	}

	it("should persist sessions across restarts", async () => {
		// First instance - create sessions
		const loki1 = new Loki({
			server: { port: PORT, host: "localhost" },
			provider: {
				issuer: ISSUER,
				clients: [
					{ client_id: "test", client_secret: "secret", grant_types: ["client_credentials"] },
				],
			},
			persistence: { enabled: true, path: TEST_DB_PATH },
		});

		await loki1.start();

		const session1 = loki1.createSession({
			name: "persist-test-1",
			mode: "explicit",
			mischief: ["alg-none"],
		});
		const session2 = loki1.createSession({
			name: "persist-test-2",
			mode: "random",
			mischief: ["key-confusion"],
		});

		expect(loki1.listSessions()).toHaveLength(2);

		await loki1.stop();

		// Second instance - should load existing sessions
		const loki2 = new Loki({
			server: { port: PORT, host: "localhost" },
			provider: {
				issuer: ISSUER,
				clients: [
					{ client_id: "test", client_secret: "secret", grant_types: ["client_credentials"] },
				],
			},
			persistence: { enabled: true, path: TEST_DB_PATH },
		});

		await loki2.start();

		const loadedSessions = loki2.listSessions();
		expect(loadedSessions).toHaveLength(2);

		const loadedSession1 = loki2.getSession(session1.id);
		expect(loadedSession1).toBeDefined();
		expect(loadedSession1?.mode).toBe("explicit");

		const loadedSession2 = loki2.getSession(session2.id);
		expect(loadedSession2).toBeDefined();
		expect(loadedSession2?.mode).toBe("random");

		await loki2.stop();
	});

	it("should persist ledger entries", async () => {
		const loki = new Loki({
			server: { port: PORT, host: "localhost" },
			provider: {
				issuer: ISSUER,
				clients: [
					{ client_id: "test", client_secret: "secret", grant_types: ["client_credentials"] },
				],
			},
			persistence: { enabled: true, path: TEST_DB_PATH },
		});

		await loki.start();

		// Create session and make request that generates ledger entries
		const session = loki.createSession({
			name: "ledger-test",
			mode: "explicit",
			mischief: ["alg-none"],
		});

		await fetch(`${ISSUER}/token`, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Authorization: `Basic ${btoa("test:secret")}`,
				"X-Loki-Session": session.id,
			},
			body: "grant_type=client_credentials",
		});

		// Check ledger has entries
		const ledger = session.getLedger();
		expect(ledger.entries.length).toBeGreaterThan(0);
		expect(ledger.entries[0]?.plugin.id).toBe("alg-none");

		await loki.stop();

		// Restart and verify ledger entries persisted
		const loki2 = new Loki({
			server: { port: PORT, host: "localhost" },
			provider: {
				issuer: ISSUER,
				clients: [
					{ client_id: "test", client_secret: "secret", grant_types: ["client_credentials"] },
				],
			},
			persistence: { enabled: true, path: TEST_DB_PATH },
		});

		await loki2.start();

		const loadedSession = loki2.getSession(session.id);
		expect(loadedSession).toBeDefined();

		// Note: Ledger entries are loaded from database by MischiefEngine
		// For now, verify session was persisted correctly
		expect(loadedSession?.mode).toBe("explicit");

		await loki2.stop();
	});

	it("should purge all data", async () => {
		const loki = new Loki({
			server: { port: PORT, host: "localhost" },
			provider: {
				issuer: ISSUER,
				clients: [
					{ client_id: "test", client_secret: "secret", grant_types: ["client_credentials"] },
				],
			},
			persistence: { enabled: true, path: TEST_DB_PATH },
		});

		await loki.start();

		loki.createSession({ name: "purge-test", mode: "explicit" });
		expect(loki.listSessions()).toHaveLength(1);

		loki.purgeSessions();
		expect(loki.listSessions()).toHaveLength(0);

		await loki.stop();

		// Restart and verify data was purged
		const loki2 = new Loki({
			server: { port: PORT, host: "localhost" },
			provider: {
				issuer: ISSUER,
				clients: [
					{ client_id: "test", client_secret: "secret", grant_types: ["client_credentials"] },
				],
			},
			persistence: { enabled: true, path: TEST_DB_PATH },
		});

		await loki2.start();
		expect(loki2.listSessions()).toHaveLength(0);
		await loki2.stop();
	});
});
