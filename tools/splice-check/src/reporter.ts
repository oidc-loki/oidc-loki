/**
 * Output formatters for splice-check results.
 *
 * Supports: table (terminal), JSON (CI), markdown (reports).
 */

import type { RunResult, TestResult } from "./runner.js";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function formatResults(run: RunResult, format: "table" | "json" | "markdown"): string {
	switch (format) {
		case "table":
			return formatTable(run);
		case "json":
			return formatJson(run);
		case "markdown":
			return formatMarkdown(run);
	}
}

// ---------------------------------------------------------------------------
// Table format (terminal)
// ---------------------------------------------------------------------------

function formatTable(run: RunResult): string {
	const lines: string[] = [];

	lines.push("");
	lines.push("  splice-check results");
	lines.push(`  ${"=".repeat(70)}`);
	lines.push("");

	// Column widths
	const idWidth = 24;
	const sevWidth = 10;
	const statusWidth = 8;

	lines.push(
		`  ${"TEST".padEnd(idWidth)}${"SEVERITY".padEnd(sevWidth)}${"STATUS".padEnd(statusWidth)}REASON`,
	);
	lines.push(`  ${"-".repeat(70)}`);

	for (const r of run.results) {
		const status = verdictStatus(r);
		const icon = verdictIcon(r);
		const reason = verdictReason(r);

		lines.push(
			`  ${icon} ${r.test.id.padEnd(idWidth - 2)}${r.test.severity.padEnd(sevWidth)}${status.padEnd(statusWidth)}${reason}`,
		);
	}

	lines.push(`  ${"-".repeat(70)}`);
	lines.push("");
	lines.push(summaryLine(run));
	lines.push("");

	return lines.join("\n");
}

// ---------------------------------------------------------------------------
// JSON format (CI)
// ---------------------------------------------------------------------------

function formatJson(run: RunResult): string {
	return JSON.stringify(
		{
			results: run.results.map((r) => ({
				id: r.test.id,
				name: r.test.name,
				severity: r.test.severity,
				spec: r.test.spec,
				status: verdictStatus(r),
				reason: verdictReason(r),
				...("passed" in r.verdict && !r.verdict.passed
					? { expected: r.verdict.expected, actual: r.verdict.actual }
					: {}),
				durationMs: r.durationMs,
				logs: r.logs.length > 0 ? r.logs : undefined,
			})),
			summary: run.summary,
		},
		null,
		2,
	);
}

// ---------------------------------------------------------------------------
// Markdown format (reports)
// ---------------------------------------------------------------------------

function formatMarkdown(run: RunResult): string {
	const lines: string[] = [];

	lines.push("# splice-check Report");
	lines.push("");
	lines.push(
		`**Total:** ${run.summary.total} tests | ` +
			`**Passed:** ${run.summary.passed} | ` +
			`**Failed:** ${run.summary.failed} | ` +
			`**Skipped:** ${run.summary.skipped} | ` +
			`**Duration:** ${run.summary.durationMs}ms`,
	);
	lines.push("");
	lines.push("| Status | Test | Severity | Spec | Reason |");
	lines.push("|--------|------|----------|------|--------|");

	for (const r of run.results) {
		const status = verdictStatus(r);
		const icon = verdictIcon(r);
		const reason = verdictReason(r).replace(/\|/g, "\\|");
		lines.push(
			`| ${icon} ${status} | ${r.test.name} | ${r.test.severity} | ${r.test.spec} | ${reason} |`,
		);
	}

	// Detail sections for failures
	const failures = run.results.filter((r) => "passed" in r.verdict && !r.verdict.passed);
	if (failures.length > 0) {
		lines.push("");
		lines.push("## Failures");
		for (const r of failures) {
			if ("passed" in r.verdict && !r.verdict.passed) {
				lines.push("");
				lines.push(`### ${r.test.name} (\`${r.test.id}\`)`);
				lines.push("");
				lines.push(`- **Expected:** ${r.verdict.expected}`);
				lines.push(`- **Actual:** ${r.verdict.actual}`);
				lines.push(`- **Spec:** ${r.test.spec}`);
				lines.push(`- **Severity:** ${r.test.severity}`);
			}
		}
	}

	lines.push("");
	return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function verdictStatus(r: TestResult): string {
	if ("skipped" in r.verdict) return "SKIP";
	return r.verdict.passed ? "PASS" : "FAIL";
}

function verdictIcon(r: TestResult): string {
	if ("skipped" in r.verdict) return "-";
	return r.verdict.passed ? "+" : "!";
}

function verdictReason(r: TestResult): string {
	return r.verdict.reason;
}

function summaryLine(run: RunResult): string {
	const { passed, failed, skipped, total, durationMs } = run.summary;
	const parts: string[] = [];

	if (passed > 0) parts.push(`${passed} passed`);
	if (failed > 0) parts.push(`${failed} FAILED`);
	if (skipped > 0) parts.push(`${skipped} skipped`);

	return `  ${parts.join(", ")} (${total} total, ${durationMs}ms)`;
}
