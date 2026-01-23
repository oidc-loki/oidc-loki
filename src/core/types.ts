/**
 * Core types for OIDC-Loki
 */

export type SessionMode = "explicit" | "random" | "shuffled";
export type Severity = "critical" | "high" | "medium" | "low";
export type MischiefPhase = "token-signing" | "token-claims" | "response" | "discovery";

export interface LokiConfig {
	server?: ServerConfig;
	provider: ProviderConfig;
	mischief?: MischiefConfig;
	plugins?: PluginsConfig;
	ledger?: LedgerConfig;
	persistence?: PersistenceConfig;
}

export interface ServerConfig {
	port: number;
	host: string;
}

export interface ProviderConfig {
	issuer: string;
	clients: ClientConfig[];
}

export interface ClientConfig {
	client_id: string;
	client_secret?: string;
	redirect_uris?: string[];
	grant_types?: string[];
}

export interface MischiefConfig {
	enabled: string[];
	profiles: Record<string, string[]>;
}

export interface PluginsConfig {
	customDir?: string;
	disabled?: string[];
}

export interface LedgerConfig {
	autoExport?: boolean;
	exportPath?: string;
	formats: ("json" | "junit")[];
}

export interface PersistenceConfig {
	enabled: boolean;
	path: string;
}

export interface SessionConfig {
	name?: string;
	mode: SessionMode;
	mischief: string[];
	probability?: number;
}

export interface Session {
	id: string;
	name?: string;
	mode: SessionMode;
	mischief: string[];
	probability?: number;
	startedAt: Date;
	endedAt?: Date;
	shuffleQueue?: string[];
}

export const DEFAULT_CONFIG: Required<
	Pick<LokiConfig, "server" | "mischief" | "plugins" | "ledger" | "persistence">
> = {
	server: {
		port: 3000,
		host: "localhost",
	},
	mischief: {
		enabled: [],
		profiles: {
			"chaos-level-1": ["temporal-tampering", "latency-injection"],
			"chaos-level-2": ["alg-none", "key-confusion"],
			"full-madness": ["alg-none", "key-confusion", "temporal-tampering", "latency-injection"],
		},
	},
	plugins: {
		customDir: "./plugins",
	},
	ledger: {
		autoExport: false,
		exportPath: "./ledger",
		formats: ["json"],
	},
	persistence: {
		enabled: true,
		path: "./data/loki.db",
	},
};
