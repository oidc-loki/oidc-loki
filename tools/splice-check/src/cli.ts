#!/usr/bin/env node

/**
 * splice-check CLI — validates AS resistance to delegation chain splicing.
 *
 * Usage:
 *   splice-check --config target.toml
 *   splice-check --config target.toml --format json
 *   splice-check --config target.toml --test basic-splice --test aud-sub-binding
 *   splice-check --config target.toml --verbose
 */

import { program } from "commander";
import { OAuthClient } from "./client.js";
import { ConfigError, type SpliceCheckConfig, loadConfig } from "./config.js";
import { formatResults } from "./reporter.js";
import { type RunnerOptions, runTests } from "./runner.js";
import { allTests, getTestIds } from "./tests/index.js";

program
	.name("splice-check")
	.description(
		"Validate OAuth 2.0 Authorization Server resistance to delegation chain splicing attacks (RFC 8693)",
	)
	.version("0.1.0")
	.requiredOption("-c, --config <path>", "Path to TOML config file")
	.option("-f, --format <format>", "Output format: table, json, markdown", "table")
	.option("-t, --test <id...>", "Run specific test(s) by ID")
	.option("-v, --verbose", "Enable verbose logging", false)
	.option("--list", "List available tests and exit")
	.action(runCli);

program.parse();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function runCli(opts: CliOptions): Promise<void> {
	if (opts.list) {
		listTests();
		return;
	}

	try {
		const config = loadConfig(opts.config);
		applyOverrides(config, opts);
		validateTestFilter(opts.test);

		const client = new OAuthClient(config.target, config.clients);
		printBanner(config, opts);

		const runnerOptions = buildRunnerOptions(config, opts);
		const result = await runTests(allTests, config, client, runnerOptions);

		console.log(formatResults(result, config.output.format));

		if (result.summary.failed > 0) {
			process.exit(1);
		}
	} catch (err) {
		if (err instanceof ConfigError) {
			console.error(err.message);
			process.exit(2);
		}
		throw err;
	}
}

function applyOverrides(config: SpliceCheckConfig, opts: CliOptions): void {
	if (opts.format) {
		config.output.format = opts.format as "table" | "json" | "markdown";
	}
	if (opts.verbose) {
		config.output.verbose = true;
	}
}

function validateTestFilter(testIds: string[] | undefined): void {
	if (!testIds) return;
	const validIds = getTestIds();
	for (const id of testIds) {
		if (!validIds.includes(id)) {
			console.error(`Unknown test ID: "${id}"`);
			console.error(`Available: ${validIds.join(", ")}`);
			process.exit(1);
		}
	}
}

function printBanner(config: SpliceCheckConfig, opts: CliOptions): void {
	if (config.output.format !== "table") return;
	const testCount = opts.test ? opts.test.length : allTests.length;
	console.log(`
  \x1b[33m⟐─────⟐\x1b[0m  \x1b[1msplice-check\x1b[0m v0.1.0
  \x1b[33m│\x1b[31m ╱ ╲ \x1b[33m│\x1b[0m  \x1b[2mDelegation Chain Security Scanner\x1b[0m
  \x1b[33m│\x1b[31m╱   ╲\x1b[33m│\x1b[0m  \x1b[2mPart of the OIDC-Loki project\x1b[0m
  \x1b[33m⟐─────⟐\x1b[0m
  \x1b[36m─ ─ ◆\x1b[31m ╳ \x1b[36m◆ ─ ─\x1b[0m  \x1b[2mBreaking chains, finding trust gaps\x1b[0m

  Target: ${config.target.token_endpoint}
  Tests:  ${testCount}
`);
}

function buildRunnerOptions(config: SpliceCheckConfig, opts: CliOptions): RunnerOptions {
	const runnerOptions: RunnerOptions = {
		verbose: config.output.verbose,
		bailOnBaselineFailure: true,
	};
	if (opts.test) {
		runnerOptions.testFilter = opts.test;
	}
	if (config.output.format === "table") {
		runnerOptions.onTestStart = (test) => process.stdout.write(`  Running ${test.id}...`);
		runnerOptions.onTestComplete = (r) => {
			const status = "skipped" in r.verdict ? "SKIP" : r.verdict.passed ? "PASS" : "FAIL";
			console.log(` ${status}`);
		};
	}
	return runnerOptions;
}

function listTests(): void {
	console.log("\nAvailable tests:\n");
	for (const test of allTests) {
		console.log(`  ${test.id.padEnd(28)} [${test.severity.padEnd(8)}] ${test.name}`);
		console.log(`${"".padEnd(30)} ${test.spec}`);
		console.log("");
	}
}

interface CliOptions {
	config: string;
	format?: string;
	test?: string[];
	verbose?: boolean;
	list?: boolean;
}
