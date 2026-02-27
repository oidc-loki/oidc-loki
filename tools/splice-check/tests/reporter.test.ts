import { describe, expect, it } from "vitest";
import { formatResults } from "../src/reporter.js";
import type { RunResult } from "../src/runner.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const passResult: RunResult = {
	results: [
		{
			test: {
				id: "valid-delegation",
				name: "Valid Delegation",
				severity: "critical",
				spec: "RFC 8693",
			},
			verdict: { passed: true, reason: "AS accepted valid delegation" },
			durationMs: 42,
			logs: [],
		},
		{
			test: {
				id: "basic-splice",
				name: "Basic Chain Splice",
				severity: "critical",
				spec: "RFC 8693",
			},
			verdict: { passed: true, reason: "AS rejected with HTTP 400" },
			durationMs: 33,
			logs: [],
		},
	],
	summary: { total: 2, passed: 2, failed: 0, skipped: 0, durationMs: 75 },
};

const mixedResult: RunResult = {
	results: [
		{
			test: {
				id: "valid-delegation",
				name: "Valid Delegation",
				severity: "critical",
				spec: "RFC 8693",
			},
			verdict: { passed: true, reason: "AS accepted valid delegation" },
			durationMs: 42,
			logs: [],
		},
		{
			test: {
				id: "basic-splice",
				name: "Basic Chain Splice",
				severity: "critical",
				spec: "RFC 8693",
			},
			verdict: {
				passed: false,
				reason: "AS accepted spliced tokens",
				expected: "HTTP 400",
				actual: "HTTP 200",
			},
			durationMs: 33,
			logs: [],
		},
		{
			test: {
				id: "may-act-enforcement",
				name: "may_act Enforcement",
				severity: "high",
				spec: "RFC 8693 Section 4.4",
			},
			verdict: { skipped: true, reason: "may_act not supported" },
			durationMs: 5,
			logs: [],
		},
	],
	summary: { total: 3, passed: 1, failed: 1, skipped: 1, durationMs: 80 },
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("formatResults", () => {
	describe("table format", () => {
		it("shows pass/fail/skip status", () => {
			const output = formatResults(mixedResult, "table");
			expect(output).toContain("PASS");
			expect(output).toContain("FAIL");
			expect(output).toContain("SKIP");
		});

		it("shows test IDs", () => {
			const output = formatResults(passResult, "table");
			expect(output).toContain("valid-delegation");
			expect(output).toContain("basic-splice");
		});

		it("shows summary line", () => {
			const output = formatResults(mixedResult, "table");
			expect(output).toContain("1 passed");
			expect(output).toContain("1 FAILED");
			expect(output).toContain("1 skipped");
		});

		it("shows severity", () => {
			const output = formatResults(mixedResult, "table");
			expect(output).toContain("critical");
			expect(output).toContain("high");
		});
	});

	describe("json format", () => {
		it("produces valid JSON", () => {
			const output = formatResults(passResult, "json");
			const parsed = JSON.parse(output);
			expect(parsed).toBeDefined();
			expect(parsed.results).toHaveLength(2);
			expect(parsed.summary).toBeDefined();
		});

		it("includes expected/actual for failures", () => {
			const output = formatResults(mixedResult, "json");
			const parsed = JSON.parse(output);
			const failure = parsed.results.find((r: Record<string, unknown>) => r.status === "FAIL");
			expect(failure?.expected).toBe("HTTP 400");
			expect(failure?.actual).toBe("HTTP 200");
		});

		it("includes summary totals", () => {
			const output = formatResults(mixedResult, "json");
			const parsed = JSON.parse(output);
			expect(parsed.summary.total).toBe(3);
			expect(parsed.summary.passed).toBe(1);
			expect(parsed.summary.failed).toBe(1);
			expect(parsed.summary.skipped).toBe(1);
		});

		it("excludes logs when empty", () => {
			const output = formatResults(passResult, "json");
			const parsed = JSON.parse(output);
			expect(parsed.results[0].logs).toBeUndefined();
		});
	});

	describe("markdown format", () => {
		it("includes header and table", () => {
			const output = formatResults(passResult, "markdown");
			expect(output).toContain("# splice-check Report");
			expect(output).toContain("| Status | Test |");
		});

		it("shows summary statistics", () => {
			const output = formatResults(mixedResult, "markdown");
			expect(output).toContain("**Total:** 3 tests");
			expect(output).toContain("**Passed:** 1");
			expect(output).toContain("**Failed:** 1");
		});

		it("includes failure details section", () => {
			const output = formatResults(mixedResult, "markdown");
			expect(output).toContain("## Failures");
			expect(output).toContain("### Basic Chain Splice");
			expect(output).toContain("**Expected:** HTTP 400");
			expect(output).toContain("**Actual:** HTTP 200");
		});

		it("does not include failures section when all pass", () => {
			const output = formatResults(passResult, "markdown");
			expect(output).not.toContain("## Failures");
		});

		it("escapes pipe characters in reasons", () => {
			const resultWithPipe: RunResult = {
				results: [
					{
						test: { id: "test", name: "Test", severity: "low", spec: "test" },
						verdict: { passed: true, reason: "value | other value" },
						durationMs: 1,
						logs: [],
					},
				],
				summary: { total: 1, passed: 1, failed: 0, skipped: 0, durationMs: 1 },
			};
			const output = formatResults(resultWithPipe, "markdown");
			expect(output).toContain("value \\| other value");
		});
	});
});
