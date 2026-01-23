/**
 * OIDC-Loki - Security Chaos Engineering for OIDC
 *
 * Library entry point for programmatic usage in test suites.
 */

export { Loki, SessionHandle } from "./core/loki.js";
export type {
	LokiConfig,
	ServerConfig,
	ProviderConfig,
	ClientConfig,
	MischiefConfig,
	PluginsConfig,
	LedgerConfig,
	PersistenceConfig,
	SessionConfig,
	Session,
	SessionMode,
	Severity,
	MischiefPhase,
} from "./core/types.js";

export type {
	MischiefPlugin,
	SpecReference,
	MischiefContext,
	MischiefResult,
	TokenContext,
	JWTHeader,
	JWTClaims,
	ResponseContext,
	PluginConfig,
	SessionInfo,
} from "./plugins/types.js";

export type {
	MischiefLedger,
	LedgerEntry,
	LedgerMeta,
	LedgerSummary,
	OutcomeReport,
} from "./ledger/types.js";

export { PluginRegistry } from "./plugins/registry.js";
