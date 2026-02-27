/**
 * splice-check library entry point.
 *
 * Exports the public API for programmatic use (e.g., from oidc-loki Phase C).
 */

// Core runner
export { runTests } from "./runner.js";
export type { RunResult, RunSummary, RunnerOptions, TestResult } from "./runner.js";

// Reporter
export { formatResults } from "./reporter.js";

// Config
export { loadConfig, ConfigError } from "./config.js";
export type { SpliceCheckConfig, TargetConfig, ClientConfig, OutputConfig } from "./config.js";

// OAuth client
export { OAuthClient, OAuthError } from "./client.js";
export type { TokenExchangeParams } from "./client.js";

// Test types and registry
export { allTests, getTestById, getTestIds } from "./tests/index.js";
export type {
	AttackTest,
	AttackResponse,
	SetupResult,
	TestContext,
	TestVerdict,
} from "./tests/types.js";
export { TOKEN_TYPE, GRANT_TYPE_TOKEN_EXCHANGE } from "./tests/types.js";
