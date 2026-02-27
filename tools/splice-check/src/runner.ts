/**
 * Test runner that orchestrates the setup → attack → verify lifecycle
 * for each AttackTest.
 */

import type { OAuthClient } from "./client.js";
import type { SpliceCheckConfig } from "./config.js";
import { redactTokens } from "./tests/helpers.js";
import type { AttackTest, SetupResult, TestContext, TestVerdict } from "./tests/types.js";

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface TestResult {
	test: {
		id: string;
		name: string;
		severity: string;
		spec: string;
	};
	verdict: TestVerdict;
	durationMs: number;
	logs: string[];
}

export interface RunResult {
	results: TestResult[];
	summary: RunSummary;
}

export interface RunSummary {
	total: number;
	passed: number;
	failed: number;
	skipped: number;
	durationMs: number;
}

// ---------------------------------------------------------------------------
// Runner options
// ---------------------------------------------------------------------------

export interface RunnerOptions {
	/** Filter to specific test IDs */
	testFilter?: string[];
	/** Enable verbose logging */
	verbose?: boolean;
	/** Stop running tests if the baseline (valid-delegation) fails */
	bailOnBaselineFailure?: boolean;
	/** Callback for live progress updates */
	onTestStart?: (test: AttackTest) => void;
	onTestComplete?: (result: TestResult) => void;
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export async function runTests(
	tests: AttackTest[],
	config: SpliceCheckConfig,
	client: OAuthClient,
	options: RunnerOptions = {},
): Promise<RunResult> {
	const filtered = options.testFilter
		? tests.filter((t) => options.testFilter?.includes(t.id))
		: tests;

	const results: TestResult[] = [];
	const runStart = performance.now();

	let baselineFailed = false;

	for (const test of filtered) {
		// Short-circuit: if baseline failed and bail is enabled, skip remaining
		if (baselineFailed && options.bailOnBaselineFailure) {
			results.push({
				test: pick(test),
				verdict: {
					skipped: true,
					reason: "Skipped — baseline (valid-delegation) failed",
				},
				durationMs: 0,
				logs: [],
			});
			options.onTestComplete?.(results[results.length - 1] as TestResult);
			continue;
		}

		options.onTestStart?.(test);

		const result = await runSingleTest(test, config, client, options.verbose ?? false);
		results.push(result);

		// Check if baseline failed
		if (test.id === "valid-delegation" && "passed" in result.verdict && !result.verdict.passed) {
			baselineFailed = true;
		}

		options.onTestComplete?.(result);
	}

	const runDuration = Math.round(performance.now() - runStart);

	return {
		results,
		summary: summarize(results, runDuration),
	};
}

// ---------------------------------------------------------------------------
// Single test execution
// ---------------------------------------------------------------------------

async function runSingleTest(
	test: AttackTest,
	config: SpliceCheckConfig,
	client: OAuthClient,
	verbose: boolean,
): Promise<TestResult> {
	const logs: string[] = [];
	let knownTokens: Record<string, string> = {};
	const log = (msg: string) => {
		if (verbose) {
			logs.push(redactTokens(msg, knownTokens));
		}
	};

	const ctx: TestContext = { config, client, log };
	const testStart = performance.now();

	try {
		// Phase 1: Setup
		log(`[setup] Starting setup for ${test.id}`);
		let setupResult: SetupResult;
		try {
			setupResult = await test.setup(ctx);
			knownTokens = setupResult.tokens;
			log(`[setup] Obtained ${Object.keys(setupResult.tokens).length} token(s)`);
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			return {
				test: pick(test),
				verdict: { skipped: true, reason: `Setup failed: ${message}` },
				durationMs: elapsed(testStart),
				logs,
			};
		}

		// Phase 2: Attack
		log(`[attack] Sending attack request for ${test.id}`);
		const response = await test.attack(ctx, setupResult);
		log(`[attack] Response: HTTP ${response.status} (${response.durationMs}ms)`);

		// Phase 3: Verify
		const verdict = test.verify(response, setupResult);
		log(
			`[verify] Verdict: ${"passed" in verdict && verdict.passed ? "PASS" : "skipped" in verdict ? "SKIP" : "FAIL"}`,
		);

		return {
			test: pick(test),
			verdict,
			durationMs: elapsed(testStart),
			logs,
		};
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			test: pick(test),
			verdict: {
				passed: false,
				reason: `Unexpected error: ${message}`,
				expected: "Test to complete without errors",
				actual: message,
			},
			durationMs: elapsed(testStart),
			logs,
		};
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function pick(test: AttackTest) {
	return {
		id: test.id,
		name: test.name,
		severity: test.severity,
		spec: test.spec,
	};
}

function elapsed(start: number): number {
	return Math.round(performance.now() - start);
}

function summarize(results: TestResult[], durationMs: number): RunSummary {
	let passed = 0;
	let failed = 0;
	let skipped = 0;

	for (const r of results) {
		if ("skipped" in r.verdict) {
			skipped++;
		} else if (r.verdict.passed) {
			passed++;
		} else {
			failed++;
		}
	}

	return { total: results.length, passed, failed, skipped, durationMs };
}
