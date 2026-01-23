import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Loki } from "../../src/index.js";

describe("Mischief Integration", () => {
	let loki: Loki;
	const PORT = 9876;
	const ISSUER = `http://localhost:${PORT}`;

	beforeAll(async () => {
		loki = new Loki({
			server: { port: PORT, host: "localhost" },
			provider: {
				issuer: ISSUER,
				clients: [
					{
						client_id: "test-client",
						client_secret: "test-secret",
						grant_types: ["client_credentials"],
					},
				],
			},
			// Disable persistence for clean test runs
			persistence: { enabled: false, path: "" },
		});
		await loki.start();
	});

	afterAll(async () => {
		await loki.stop();
	});

	describe("alg:none attack", () => {
		it("should produce unsigned token when alg-none is enabled", async () => {
			// Create session with alg-none enabled
			const session = loki.createSession({
				name: "alg-none-test",
				mode: "explicit",
				mischief: ["alg-none"],
			});

			// Request a token with the session header
			const response = await fetch(`${ISSUER}/token`, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: `Basic ${btoa("test-client:test-secret")}`,
					"X-Loki-Session": session.id,
				},
				body: "grant_type=client_credentials",
			});

			expect(response.ok).toBe(true);

			const data = (await response.json()) as { access_token?: string; id_token?: string };

			// The token should be modified
			if (data.access_token?.includes(".")) {
				const parts = data.access_token.split(".");
				expect(parts).toHaveLength(3);

				// Decode header
				const header = JSON.parse(atob(parts[0]?.replace(/-/g, "+").replace(/_/g, "/")));
				expect(header.alg).toBe("none");

				// Signature should be empty
				expect(parts[2]).toBe("");
			}

			// Check ledger
			const ledger = session.getLedger();
			expect(ledger.entries.length).toBeGreaterThan(0);
			expect(ledger.entries[0]?.plugin.id).toBe("alg-none");
		});
	});

	describe("key-confusion attack", () => {
		it("should change RS256 to HS256 when key-confusion is enabled", async () => {
			// Create session with key-confusion enabled
			const session = loki.createSession({
				name: "key-confusion-test",
				mode: "explicit",
				mischief: ["key-confusion"],
			});

			// Request a token with the session header
			const response = await fetch(`${ISSUER}/token`, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: `Basic ${btoa("test-client:test-secret")}`,
					"X-Loki-Session": session.id,
				},
				body: "grant_type=client_credentials",
			});

			expect(response.ok).toBe(true);

			const data = (await response.json()) as { access_token?: string };

			// The token should have alg changed to HS256
			if (data.access_token?.includes(".")) {
				const parts = data.access_token.split(".");
				expect(parts).toHaveLength(3);

				// Decode header
				const header = JSON.parse(atob(parts[0]?.replace(/-/g, "+").replace(/_/g, "/")));
				expect(header.alg).toBe("HS256");

				// Should have a signature (not empty like alg:none)
				expect(parts[2]).not.toBe("");
			}

			// Check ledger
			const ledger = session.getLedger();
			expect(ledger.entries.length).toBeGreaterThan(0);
			expect(ledger.entries[0]?.plugin.id).toBe("key-confusion");
		});
	});

	describe("temporal-tampering attack", () => {
		it("should produce expired token when temporal-tampering is enabled", async () => {
			// Create session with temporal-tampering enabled
			const session = loki.createSession({
				name: "temporal-test",
				mode: "explicit",
				mischief: ["temporal-tampering"],
			});

			// Request a token with the session header
			const response = await fetch(`${ISSUER}/token`, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: `Basic ${btoa("test-client:test-secret")}`,
					"X-Loki-Session": session.id,
				},
				body: "grant_type=client_credentials",
			});

			expect(response.ok).toBe(true);

			const _data = (await response.json()) as { access_token?: string };

			// Check ledger recorded the tampering
			const ledger = session.getLedger();
			expect(ledger.entries.length).toBeGreaterThan(0);

			const temporalEntry = ledger.entries.find((e) => e.plugin.id === "temporal-tampering");
			expect(temporalEntry).toBeDefined();
			expect(temporalEntry?.evidence.mode).toBe("expired");
		});
	});

	describe("session modes", () => {
		it("should not apply mischief without session header", async () => {
			// Request token WITHOUT session header
			const response = await fetch(`${ISSUER}/token`, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: `Basic ${btoa("test-client:test-secret")}`,
					// No X-Loki-Session header
				},
				body: "grant_type=client_credentials",
			});

			expect(response.ok).toBe(true);

			const data = (await response.json()) as { access_token?: string };

			// Token should be normal (not alg:none)
			if (data.access_token?.includes(".")) {
				const parts = data.access_token.split(".");
				const header = JSON.parse(atob(parts[0]?.replace(/-/g, "+").replace(/_/g, "/")));
				// Should NOT be alg:none
				expect(header.alg).not.toBe("none");
			}
		});

		it("should apply mischief only to session with enabled plugins", async () => {
			// Create session WITHOUT any mischief
			const cleanSession = loki.createSession({
				name: "clean-session",
				mode: "explicit",
				mischief: [], // No mischief enabled
			});

			// Request token with clean session
			const response = await fetch(`${ISSUER}/token`, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Authorization: `Basic ${btoa("test-client:test-secret")}`,
					"X-Loki-Session": cleanSession.id,
				},
				body: "grant_type=client_credentials",
			});

			expect(response.ok).toBe(true);

			// Ledger should be empty
			const ledger = cleanSession.getLedger();
			expect(ledger.entries).toHaveLength(0);
		});
	});

	describe("ledger tracking", () => {
		it("should track multiple mischief applications", async () => {
			// Create session with multiple mischief plugins
			const session = loki.createSession({
				name: "multi-mischief",
				mode: "explicit",
				mischief: ["alg-none", "temporal-tampering"],
			});

			// Make multiple requests
			for (let i = 0; i < 3; i++) {
				await fetch(`${ISSUER}/token`, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: `Basic ${btoa("test-client:test-secret")}`,
						"X-Loki-Session": session.id,
					},
					body: "grant_type=client_credentials",
				});
			}

			const ledger = session.getLedger();

			// Should have entries for both plugins across 3 requests
			// (alg-none for signing, temporal-tampering for claims)
			expect(ledger.entries.length).toBeGreaterThan(0);
			expect(ledger.summary.requestsWithMischief).toBeGreaterThan(0);

			// Check plugin breakdown
			const pluginIds = ledger.entries.map((e) => e.plugin.id);
			expect(pluginIds).toContain("alg-none");
			expect(pluginIds).toContain("temporal-tampering");
		});
	});
});
