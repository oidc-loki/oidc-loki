/**
 * Configuration loader for splice-check.
 *
 * Reads a TOML config file that describes:
 *   - target AS endpoints (token, jwks, issuer)
 *   - client credentials for test actors
 *   - authentication method
 *   - output preferences
 */

import { readFileSync } from "node:fs";
import { parse } from "smol-toml";

// ---------------------------------------------------------------------------
// Config types
// ---------------------------------------------------------------------------

export interface SpliceCheckConfig {
	target: TargetConfig;
	clients: Record<string, ClientConfig>;
	output: OutputConfig;
}

export interface TargetConfig {
	/** Token exchange endpoint URL */
	token_endpoint: string;
	/** JWKS endpoint for validating tokens */
	jwks_endpoint: string;
	/** Expected issuer value in tokens */
	issuer: string;
	/** How clients authenticate to the AS */
	auth: AuthConfig;
	/** Revocation endpoint (defaults to token_endpoint with /token replaced by /revoke) */
	revocation_endpoint?: string;
	/** Introspection endpoint (defaults to token_endpoint with /token replaced by /introspect) */
	introspection_endpoint?: string;
	/** Request timeout in milliseconds (default: 30000) */
	timeout?: number;
}

export interface AuthConfig {
	method: "client_secret_post" | "client_secret_basic";
}

export interface ClientConfig {
	client_id: string;
	client_secret: string;
	/** Grant type used to obtain initial tokens (default: client_credentials) */
	grant_type?: string;
	/** Scopes to request */
	scope?: string;
}

export interface OutputConfig {
	format: "table" | "json" | "markdown";
	verbose: boolean;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_OUTPUT: OutputConfig = {
	format: "table",
	verbose: false,
};

const DEFAULT_AUTH: AuthConfig = {
	method: "client_secret_post",
};

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

export function loadConfig(path: string): SpliceCheckConfig {
	const raw = interpolateEnvVars(readFileSync(path, "utf-8"));
	const parsed = parse(raw) as RawConfig;

	const target = validateTarget(parsed);
	validateClients(parsed);

	return {
		target,
		clients: parsed.clients as Record<string, ClientConfig>,
		output: validateOutput(parsed),
	};
}

function validateTarget(parsed: RawConfig): TargetConfig {
	if (!parsed.target) {
		throw new ConfigError("Missing [target] section");
	}
	if (!parsed.target.token_endpoint) {
		throw new ConfigError("Missing target.token_endpoint");
	}
	if (!parsed.target.jwks_endpoint) {
		throw new ConfigError("Missing target.jwks_endpoint");
	}
	if (!parsed.target.issuer) {
		throw new ConfigError("Missing target.issuer");
	}

	const authMethod = parsed.target.auth?.method ?? DEFAULT_AUTH.method;
	if (authMethod !== "client_secret_post" && authMethod !== "client_secret_basic") {
		throw new ConfigError(
			`Invalid auth method: "${authMethod}" (must be client_secret_post or client_secret_basic)`,
		);
	}

	const result: TargetConfig = {
		token_endpoint: parsed.target.token_endpoint,
		jwks_endpoint: parsed.target.jwks_endpoint,
		issuer: parsed.target.issuer,
		auth: { method: authMethod },
	};

	if (parsed.target.revocation_endpoint) {
		result.revocation_endpoint = parsed.target.revocation_endpoint;
	}
	if (parsed.target.introspection_endpoint) {
		result.introspection_endpoint = parsed.target.introspection_endpoint;
	}
	if (parsed.target.timeout !== undefined) {
		result.timeout = parsed.target.timeout;
	}

	return result;
}

function validateClients(parsed: RawConfig): void {
	if (!parsed.clients || Object.keys(parsed.clients).length === 0) {
		throw new ConfigError("Missing [clients] section — need at least alice, agent-a, agent-n");
	}

	for (const name of ["alice", "agent-a", "agent-n"]) {
		if (!parsed.clients[name]) {
			throw new ConfigError(`Missing required client: [clients.${name}]`);
		}
		const client = parsed.clients[name];
		if (!client?.client_id || !client.client_secret) {
			throw new ConfigError(`Client [clients.${name}] missing client_id or client_secret`);
		}
	}
}

function validateOutput(parsed: RawConfig): OutputConfig {
	const format = parsed.output?.format ?? DEFAULT_OUTPUT.format;
	if (format !== "table" && format !== "json" && format !== "markdown") {
		throw new ConfigError(`Invalid output format: "${format}" (must be table, json, or markdown)`);
	}

	return {
		format,
		verbose: parsed.output?.verbose ?? DEFAULT_OUTPUT.verbose,
	};
}

// ---------------------------------------------------------------------------
// Error class
// ---------------------------------------------------------------------------

export class ConfigError extends Error {
	constructor(message: string) {
		super(`Config error: ${message}`);
		this.name = "ConfigError";
	}
}

// ---------------------------------------------------------------------------
// Raw parsed shape (before validation)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Env var interpolation
// ---------------------------------------------------------------------------

/**
 * Replace ${ENV_VAR} patterns with environment variable values.
 * Throws ConfigError if a referenced variable is not set.
 */
function interpolateEnvVars(content: string): string {
	return content.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_match, name: string) => {
		const value = process.env[name];
		if (value === undefined) {
			throw new ConfigError(
				`Environment variable "${name}" is not set (referenced as \${${name}})`,
			);
		}
		return value;
	});
}

// ---------------------------------------------------------------------------
// Raw parsed shape (before validation)
// ---------------------------------------------------------------------------

interface RawConfig {
	target?: {
		token_endpoint?: string;
		jwks_endpoint?: string;
		issuer?: string;
		auth?: { method?: string };
		revocation_endpoint?: string;
		introspection_endpoint?: string;
		timeout?: number;
	};
	clients?: Record<
		string,
		{ client_id?: string; client_secret?: string; grant_type?: string; scope?: string }
	>;
	output?: { format?: string; verbose?: boolean };
}
