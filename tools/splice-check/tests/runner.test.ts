import { describe, expect, it } from "vitest";
import type { OAuthClient } from "../src/client.js";
import type { SpliceCheckConfig } from "../src/config.js";
import { runTests } from "../src/runner.js";
import type { AttackTest, SetupResult, TestContext } from "../src/tests/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const mockConfig: SpliceCheckConfig = {
	target: {
		token_endpoint: "https://example.com/token",
		jwks_endpoint: "https://example.com/jwks",
		issuer: "https://example.com",
		auth: { method: "client_secret_post" },
	},
	clients: {
		alice: { client_id: "a", client_secret: "s" },
		"agent-a": { client_id: "b", client_secret: "s" },
		"agent-n": { client_id: "c", client_secret: "s" },
	},
	output: { format: "table", verbose: false },
};

const mockClient = {} as OAuthClient;

function makeTest(overrides: Partial<AttackTest> & { id: string }): AttackTest {
	return {
		name: overrides.id,
		description: "test",
		spec: "test",
		severity: "medium",
		setup: async () => ({ tokens: {} }),
		attack: async () => ({ status: 200, body: {}, headers: {}, durationMs: 1 }),
		verify: () => ({ passed: true, reason: "ok" }),
		...overrides,
	};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("runTests", () => {
	it("runs all tests and returns results", async () => {
		const tests = [makeTest({ id: "test-1" }), makeTest({ id: "test-2" })];

		const result = await runTests(tests, mockConfig, mockClient);
		expect(result.results).toHaveLength(2);
		expect(result.summary.total).toBe(2);
		expect(result.summary.passed).toBe(2);
		expect(result.summary.failed).toBe(0);
		expect(result.summary.skipped).toBe(0);
	});

	it("handles failing tests", async () => {
		const tests = [
			makeTest({
				id: "fail-test",
				verify: () => ({
					passed: false,
					reason: "AS accepted bad token",
					expected: "HTTP 400",
					actual: "HTTP 200",
				}),
			}),
		];

		const result = await runTests(tests, mockConfig, mockClient);
		expect(result.summary.failed).toBe(1);
		expect(result.results[0]?.verdict).toEqual({
			passed: false,
			reason: "AS accepted bad token",
			expected: "HTTP 400",
			actual: "HTTP 200",
		});
	});

	it("handles skipped tests", async () => {
		const tests = [
			makeTest({
				id: "skip-test",
				verify: () => ({ skipped: true, reason: "Feature not supported" }),
			}),
		];

		const result = await runTests(tests, mockConfig, mockClient);
		expect(result.summary.skipped).toBe(1);
	});

	it("handles setup failures gracefully (marks as skipped)", async () => {
		const tests = [
			makeTest({
				id: "setup-fail",
				setup: async () => {
					throw new Error("Cannot connect to AS");
				},
			}),
		];

		const result = await runTests(tests, mockConfig, mockClient);
		expect(result.summary.skipped).toBe(1);
		const verdict = result.results[0]?.verdict;
		expect(verdict && "skipped" in verdict && verdict.skipped).toBe(true);
		expect(verdict && "reason" in verdict && verdict.reason).toContain("Setup failed");
	});

	it("handles attack phase errors (marks as failed)", async () => {
		const tests = [
			makeTest({
				id: "attack-error",
				attack: async () => {
					throw new Error("Network timeout");
				},
			}),
		];

		const result = await runTests(tests, mockConfig, mockClient);
		expect(result.summary.failed).toBe(1);
		const verdict = result.results[0]?.verdict;
		expect(verdict && "passed" in verdict && !verdict.passed).toBe(true);
	});

	it("filters tests by ID", async () => {
		const tests = [
			makeTest({ id: "test-1" }),
			makeTest({ id: "test-2" }),
			makeTest({ id: "test-3" }),
		];

		const result = await runTests(tests, mockConfig, mockClient, {
			testFilter: ["test-1", "test-3"],
		});
		expect(result.results).toHaveLength(2);
		expect(result.results.map((r) => r.test.id)).toEqual(["test-1", "test-3"]);
	});

	it("collects logs in verbose mode", async () => {
		const tests = [
			makeTest({
				id: "verbose-test",
				setup: async (ctx: TestContext) => {
					ctx.log("Setting up");
					return { tokens: {} } as SetupResult;
				},
			}),
		];

		const result = await runTests(tests, mockConfig, mockClient, { verbose: true });
		const logs = result.results[0]?.logs ?? [];
		expect(logs.some((l) => l.includes("Setting up"))).toBe(true);
	});

	it("does not collect logs when verbose is off", async () => {
		const tests = [
			makeTest({
				id: "quiet-test",
				setup: async (ctx: TestContext) => {
					ctx.log("This should not appear");
					return { tokens: {} } as SetupResult;
				},
			}),
		];

		const result = await runTests(tests, mockConfig, mockClient, { verbose: false });
		expect(result.results[0]?.logs).toEqual([]);
	});

	it("calls onTestStart and onTestComplete callbacks", async () => {
		const started: string[] = [];
		const completed: string[] = [];

		const tests = [makeTest({ id: "callback-test" })];

		await runTests(tests, mockConfig, mockClient, {
			onTestStart: (test) => started.push(test.id),
			onTestComplete: (result) => completed.push(result.test.id),
		});

		expect(started).toEqual(["callback-test"]);
		expect(completed).toEqual(["callback-test"]);
	});

	it("tracks total duration", async () => {
		const tests = [makeTest({ id: "timed-test" })];
		const result = await runTests(tests, mockConfig, mockClient);
		expect(result.summary.durationMs).toBeGreaterThanOrEqual(0);
	});

	it("includes test metadata in results", async () => {
		const tests = [
			makeTest({
				id: "meta-test",
				name: "Meta Test",
				severity: "critical",
				spec: "RFC 8693",
			}),
		];

		const result = await runTests(tests, mockConfig, mockClient);
		expect(result.results[0]?.test).toEqual({
			id: "meta-test",
			name: "Meta Test",
			severity: "critical",
			spec: "RFC 8693",
		});
	});

	it("bails on baseline failure when bailOnBaselineFailure is set", async () => {
		const tests = [
			makeTest({
				id: "valid-delegation",
				verify: () => ({
					passed: false,
					reason: "AS rejected valid delegation",
					expected: "HTTP 200",
					actual: "HTTP 400",
				}),
			}),
			makeTest({ id: "test-2" }),
			makeTest({ id: "test-3" }),
		];

		const result = await runTests(tests, mockConfig, mockClient, {
			bailOnBaselineFailure: true,
		});
		expect(result.results).toHaveLength(3);
		expect(result.summary.failed).toBe(1);
		expect(result.summary.skipped).toBe(2);
		const skipped = result.results[1]?.verdict;
		expect(skipped && "skipped" in skipped && skipped.skipped).toBe(true);
	});

	it("does not bail when bailOnBaselineFailure is false", async () => {
		const tests = [
			makeTest({
				id: "valid-delegation",
				verify: () => ({
					passed: false,
					reason: "fail",
					expected: "a",
					actual: "b",
				}),
			}),
			makeTest({ id: "test-2" }),
		];

		const result = await runTests(tests, mockConfig, mockClient, {
			bailOnBaselineFailure: false,
		});
		expect(result.summary.failed).toBe(1);
		expect(result.summary.passed).toBe(1);
	});
});
