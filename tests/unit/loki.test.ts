import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Loki } from "../../src/index.js";

describe("Loki", () => {
	describe("lifecycle", () => {
		it("should start and stop", async () => {
			const loki = new Loki({
				server: { port: 9999, host: "localhost" },
				provider: {
					issuer: "http://localhost:9999",
					clients: [{ client_id: "test", client_secret: "secret" }],
				},
				persistence: { enabled: false, path: "" },
			});

			expect(loki.isRunning).toBe(false);
			await loki.start();
			expect(loki.isRunning).toBe(true);
			expect(loki.address).toBe("http://localhost:9999");

			await loki.stop();
			expect(loki.isRunning).toBe(false);
		});

		it("should load built-in plugins", async () => {
			const loki = new Loki({
				server: { port: 9998, host: "localhost" },
				provider: {
					issuer: "http://localhost:9998",
					clients: [],
				},
				persistence: { enabled: false, path: "" },
			});

			await loki.start();

			expect(loki.plugins.count).toBe(36);
			expect(loki.plugins.has("alg-none")).toBe(true);
			expect(loki.plugins.has("key-confusion")).toBe(true);
			expect(loki.plugins.has("issuer-confusion")).toBe(true);
			expect(loki.plugins.has("audience-confusion")).toBe(true);
			expect(loki.plugins.has("subject-manipulation")).toBe(true);
			expect(loki.plugins.has("nonce-bypass")).toBe(true);
			expect(loki.plugins.has("state-bypass")).toBe(true);
			expect(loki.plugins.has("scope-injection")).toBe(true);
			expect(loki.plugins.has("discovery-confusion")).toBe(true);
			expect(loki.plugins.has("jwks-injection")).toBe(true);
			expect(loki.plugins.has("token-type-confusion")).toBe(true);

			await loki.stop();
		});
	});

	describe("sessions", () => {
		let loki: Loki;

		beforeAll(async () => {
			loki = new Loki({
				server: { port: 9997, host: "localhost" },
				provider: {
					issuer: "http://localhost:9997",
					clients: [],
				},
				persistence: { enabled: false, path: "" },
			});
			await loki.start();
		});

		afterAll(async () => {
			await loki.stop();
		});

		it("should create explicit session", () => {
			const session = loki.createSession({ mode: "explicit" });
			expect(session.id).toMatch(/^sess_/);
			expect(session.mode).toBe("explicit");
		});

		it("should create random session", () => {
			const session = loki.createSession({
				mode: "random",
				mischief: ["alg-none", "key-confusion"],
				probability: 0.5,
			});
			expect(session.mode).toBe("random");
		});

		it("should create shuffled session", () => {
			const session = loki.createSession({
				mode: "shuffled",
				mischief: ["alg-none", "key-confusion", "temporal-tampering"],
			});
			expect(session.mode).toBe("shuffled");
		});

		it("should enable mischief in explicit mode", () => {
			const session = loki.createSession({ mode: "explicit" });
			session.enable("alg-none");
			// No error means success
		});

		it("should throw when enabling mischief in random mode", () => {
			const session = loki.createSession({ mode: "random", mischief: [] });
			expect(() => session.enable("alg-none")).toThrow(/Cannot enable plugins in random mode/);
		});

		it("should get empty ledger for new session", () => {
			const session = loki.createSession();
			const ledger = session.getLedger();

			expect(ledger.meta.sessionId).toBe(session.id);
			expect(ledger.summary.totalRequests).toBe(0);
			expect(ledger.entries).toHaveLength(0);
		});

		it("should list and purge sessions", () => {
			loki.purgeSessions();
			expect(loki.listSessions()).toHaveLength(0);

			loki.createSession({ name: "session-1" });
			loki.createSession({ name: "session-2" });
			expect(loki.listSessions()).toHaveLength(2);

			loki.purgeSessions();
			expect(loki.listSessions()).toHaveLength(0);
		});
	});

	describe("plugins", () => {
		it("should register custom plugin", async () => {
			const loki = new Loki({
				server: { port: 9996, host: "localhost" },
				provider: {
					issuer: "http://localhost:9996",
					clients: [],
				},
				persistence: { enabled: false, path: "" },
			});

			await loki.start();

			loki.register({
				id: "custom-mischief",
				name: "Custom Mischief",
				severity: "low",
				phase: "response",
				spec: { description: "Test plugin" },
				description: "A test plugin",
				apply: async () => ({
					applied: true,
					mutation: "test",
					evidence: {},
				}),
			});

			expect(loki.plugins.count).toBe(37);
			expect(loki.plugins.has("custom-mischief")).toBe(true);

			await loki.stop();
		});

		it("should get plugins by phase", async () => {
			const loki = new Loki({
				server: { port: 9995, host: "localhost" },
				provider: { issuer: "http://localhost:9995", clients: [] },
				persistence: { enabled: false, path: "" },
			});
			await loki.start();

			const tokenSigningPlugins = loki.plugins.getByPhase("token-signing");
			expect(tokenSigningPlugins).toHaveLength(11); // alg-none, key-confusion, kid-manipulation, token-type-confusion, weak-algorithms, jku-injection, x5u-injection, embedded-jwk-attack, crit-header-bypass, curve-confusion, jwks-domain-mismatch
			expect(tokenSigningPlugins.map((p) => p.id)).toContain("alg-none");
			expect(tokenSigningPlugins.map((p) => p.id)).toContain("key-confusion");
			expect(tokenSigningPlugins.map((p) => p.id)).toContain("kid-manipulation");
			expect(tokenSigningPlugins.map((p) => p.id)).toContain("token-type-confusion");

			await loki.stop();
		});

		it("should get plugins by severity", async () => {
			const loki = new Loki({
				server: { port: 9994, host: "localhost" },
				provider: { issuer: "http://localhost:9994", clients: [] },
				persistence: { enabled: false, path: "" },
			});
			await loki.start();

			const criticalPlugins = loki.plugins.getBySeverity("critical");
			expect(criticalPlugins).toHaveLength(15); // includes new critical plugins: weak-algorithms, jku-injection, x5u-injection, embedded-jwk-attack, curve-confusion, jwks-domain-mismatch, iss-in-response-attack

			await loki.stop();
		});
	});
});
