import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Loki } from "../../src/index.js";

describe("Admin API", () => {
	let loki: Loki;
	const PORT = 9877;
	const ISSUER = `http://localhost:${PORT}`;
	const ADMIN_URL = `${ISSUER}/admin`;

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
			persistence: { enabled: false, path: "" },
		});
		await loki.start();
	});

	afterAll(async () => {
		await loki.stop();
	});

	describe("health endpoint", () => {
		it("should return health status", async () => {
			const response = await fetch(`${ISSUER}/health`);
			expect(response.ok).toBe(true);

			const data = await response.json();
			expect(data.status).toBe("ok");
			expect(data.issuer).toBe(ISSUER);
			expect(data.plugins).toBe(11);
		});

		it("should return health via admin endpoint", async () => {
			const response = await fetch(`${ADMIN_URL}/health`);
			expect(response.ok).toBe(true);

			const data = await response.json();
			expect(data.status).toBe("ok");
		});
	});

	describe("sessions API", () => {
		it("should list sessions", async () => {
			// Purge first
			await fetch(`${ADMIN_URL}/sessions`, { method: "DELETE" });

			const response = await fetch(`${ADMIN_URL}/sessions`);
			expect(response.ok).toBe(true);

			const data = await response.json();
			expect(data.sessions).toEqual([]);
		});

		it("should create session via API", async () => {
			const response = await fetch(`${ADMIN_URL}/sessions`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					name: "api-test-session",
					mode: "explicit",
					mischief: ["alg-none"],
				}),
			});

			expect(response.status).toBe(201);
			const data = await response.json();
			expect(data.sessionId).toMatch(/^sess_/);
		});

		it("should get session details", async () => {
			// Create session first
			const createRes = await fetch(`${ADMIN_URL}/sessions`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: "detail-test", mode: "explicit" }),
			});
			const { sessionId } = await createRes.json();

			// Get details
			const response = await fetch(`${ADMIN_URL}/sessions/${sessionId}`);
			expect(response.ok).toBe(true);

			const data = await response.json();
			expect(data.id).toBe(sessionId);
			expect(data.mode).toBe("explicit");
			expect(data.isEnded).toBe(false);
			expect(data.summary.totalRequests).toBe(0);
		});

		it("should get session ledger", async () => {
			// Create session first
			const createRes = await fetch(`${ADMIN_URL}/sessions`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: "ledger-test", mode: "explicit" }),
			});
			const { sessionId } = await createRes.json();

			// Get full ledger
			const response = await fetch(`${ADMIN_URL}/sessions/${sessionId}/ledger`);
			expect(response.ok).toBe(true);

			const data = await response.json();
			expect(data.meta.sessionId).toBe(sessionId);
			expect(data.entries).toEqual([]);
		});

		it("should return 404 for non-existent session", async () => {
			const response = await fetch(`${ADMIN_URL}/sessions/sess_nonexistent`);
			expect(response.status).toBe(404);

			const data = await response.json();
			expect(data.error).toBe("Session not found");
		});

		it("should delete session", async () => {
			// Create session
			const createRes = await fetch(`${ADMIN_URL}/sessions`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: "delete-test" }),
			});
			const { sessionId } = await createRes.json();

			// Delete it
			const deleteRes = await fetch(`${ADMIN_URL}/sessions/${sessionId}`, {
				method: "DELETE",
			});
			expect(deleteRes.ok).toBe(true);

			// Verify it's gone
			const getRes = await fetch(`${ADMIN_URL}/sessions/${sessionId}`);
			expect(getRes.status).toBe(404);
		});

		it("should purge all sessions", async () => {
			// Create a few sessions
			await fetch(`${ADMIN_URL}/sessions`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: "purge-1" }),
			});
			await fetch(`${ADMIN_URL}/sessions`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: "purge-2" }),
			});

			// Purge
			const purgeRes = await fetch(`${ADMIN_URL}/sessions`, { method: "DELETE" });
			expect(purgeRes.ok).toBe(true);

			// Verify empty
			const listRes = await fetch(`${ADMIN_URL}/sessions`);
			const { sessions } = await listRes.json();
			expect(sessions).toHaveLength(0);
		});
	});

	describe("plugins API", () => {
		it("should list all plugins", async () => {
			const response = await fetch(`${ADMIN_URL}/plugins`);
			expect(response.ok).toBe(true);

			const data = await response.json();
			expect(data.plugins).toHaveLength(11);
			expect(data.plugins.map((p: { id: string }) => p.id)).toContain("alg-none");
			expect(data.plugins.map((p: { id: string }) => p.id)).toContain("key-confusion");
		});

		it("should get plugin details", async () => {
			const response = await fetch(`${ADMIN_URL}/plugins/alg-none`);
			expect(response.ok).toBe(true);

			const data = await response.json();
			expect(data.id).toBe("alg-none");
			expect(data.name).toBe("Algorithm None Injection");
			expect(data.severity).toBe("critical");
			expect(data.phase).toBe("token-signing");
			expect(data.spec).toBeDefined();
		});

		it("should return 404 for non-existent plugin", async () => {
			const response = await fetch(`${ADMIN_URL}/plugins/nonexistent`);
			expect(response.status).toBe(404);

			const data = await response.json();
			expect(data.error).toBe("Plugin not found");
		});

		it("should filter plugins by phase", async () => {
			const response = await fetch(`${ADMIN_URL}/plugins/phase/token-signing`);
			expect(response.ok).toBe(true);

			const data = await response.json();
			expect(data.plugins.length).toBeGreaterThan(0);
			expect(data.plugins.map((p: { id: string }) => p.id)).toContain("alg-none");
			expect(data.plugins.map((p: { id: string }) => p.id)).toContain("key-confusion");
		});

		it("should filter plugins by severity", async () => {
			const response = await fetch(`${ADMIN_URL}/plugins/severity/critical`);
			expect(response.ok).toBe(true);

			const data = await response.json();
			expect(data.plugins.length).toBe(5); // alg-none, key-confusion, issuer-confusion, audience-confusion, subject-manipulation
		});
	});

	describe("reset endpoint", () => {
		it("should reset all data", async () => {
			// Create some sessions
			await fetch(`${ADMIN_URL}/sessions`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ name: "reset-test" }),
			});

			// Reset
			const resetRes = await fetch(`${ADMIN_URL}/reset`, { method: "POST" });
			expect(resetRes.ok).toBe(true);

			const data = await resetRes.json();
			expect(data.reset).toBe(true);

			// Verify sessions cleared
			const listRes = await fetch(`${ADMIN_URL}/sessions`);
			const { sessions } = await listRes.json();
			expect(sessions).toHaveLength(0);
		});
	});
});
