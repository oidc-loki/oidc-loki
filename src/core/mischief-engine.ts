/**
 * Mischief Engine - intercepts and corrupts OIDC responses
 *
 * This is where the chaos happens. The engine intercepts token generation,
 * applies active mischief plugins, and logs everything to the ledger.
 */

import { nanoid } from "nanoid";
import type { LedgerEntry, MischiefLedger } from "../ledger/types.js";
import type { PluginRegistry } from "../plugins/registry.js";
import type { MischiefContext, MischiefPlugin, MischiefResult } from "../plugins/types.js";
import { type ForgeableToken, parseToken } from "./token-forge.js";
import type { Session } from "./types.js";

export interface MischiefEngineOptions {
	pluginRegistry: PluginRegistry;
	getPublicKey: () => Promise<string>;
	/** Optional callback for persisting ledger entries */
	onLedgerEntry?: (sessionId: string, entry: LedgerEntry) => void;
}

export interface RequestContext {
	requestId: string;
	session: Session;
	endpoint: string;
	method: string;
	timestamp: Date;
}

export interface MischiefApplication {
	pluginId: string;
	result: MischiefResult;
	plugin: MischiefPlugin;
}

/**
 * Mischief Engine - applies chaos to tokens and responses
 */
export class MischiefEngine {
	private readonly pluginRegistry: PluginRegistry;
	private readonly getPublicKey: () => Promise<string>;
	private readonly onLedgerEntry?: (sessionId: string, entry: LedgerEntry) => void;
	private readonly ledgerEntries = new Map<string, LedgerEntry[]>(); // sessionId -> entries

	constructor(options: MischiefEngineOptions) {
		this.pluginRegistry = options.pluginRegistry;
		this.getPublicKey = options.getPublicKey;
		if (options.onLedgerEntry) {
			this.onLedgerEntry = options.onLedgerEntry;
		}
	}

	/**
	 * Apply mischief to a JWT token
	 */
	async applyToToken(
		jwt: string,
		requestCtx: RequestContext,
	): Promise<{ token: string; applications: MischiefApplication[] }> {
		const plugins = this.selectPlugins(requestCtx.session, ["token-signing", "token-claims"]);

		if (plugins.length === 0) {
			return { token: jwt, applications: [] };
		}

		const publicKey = await this.getPublicKey();
		const forgeableToken = parseToken(jwt, publicKey);
		const applications: MischiefApplication[] = [];

		for (const plugin of plugins) {
			const context = this.buildTokenContext(forgeableToken, requestCtx.session, plugin);
			const result = await plugin.apply(context);

			if (result.applied) {
				applications.push({ pluginId: plugin.id, result, plugin });
				this.recordLedgerEntry(requestCtx, plugin, result);
			}
		}

		return {
			token: forgeableToken.build(),
			applications,
		};
	}

	/**
	 * Apply response-phase mischief (like latency injection)
	 */
	async applyToResponse(
		requestCtx: RequestContext,
	): Promise<{ applications: MischiefApplication[]; delayMs: number }> {
		const plugins = this.selectPlugins(requestCtx.session, ["response"]);

		if (plugins.length === 0) {
			return { applications: [], delayMs: 0 };
		}

		const applications: MischiefApplication[] = [];
		let totalDelay = 0;

		for (const plugin of plugins) {
			const startTime = Date.now();
			const context = this.buildResponseContext(requestCtx.session, plugin);
			const result = await plugin.apply(context);
			const elapsed = Date.now() - startTime;

			if (result.applied) {
				applications.push({ pluginId: plugin.id, result, plugin });
				this.recordLedgerEntry(requestCtx, plugin, result);
				totalDelay += elapsed;
			}
		}

		return { applications, delayMs: totalDelay };
	}

	/**
	 * Apply discovery-phase mischief (discovery document and JWKS manipulation)
	 */
	async applyToDiscovery(
		body: unknown,
		requestCtx: RequestContext,
	): Promise<{ body: unknown; applications: MischiefApplication[] }> {
		const plugins = this.selectPlugins(requestCtx.session, ["discovery"]);

		if (plugins.length === 0) {
			return { body, applications: [] };
		}

		const applications: MischiefApplication[] = [];
		let modifiedBody = body;

		for (const plugin of plugins) {
			const context = this.buildDiscoveryContext(modifiedBody, requestCtx.session, plugin);
			const result = await plugin.apply(context);

			if (result.applied) {
				applications.push({ pluginId: plugin.id, result, plugin });
				this.recordLedgerEntry(requestCtx, plugin, result);
				// Get the potentially modified body from the context
				if (context.response?.body !== undefined) {
					modifiedBody = context.response.body;
				}
			}
		}

		return { body: modifiedBody, applications };
	}

	/**
	 * Select which plugins to apply based on session mode
	 */
	private selectPlugins(session: Session, phases: MischiefPlugin["phase"][]): MischiefPlugin[] {
		const enabledIds = this.getEnabledPlugins(session);
		const plugins = enabledIds
			.map((id) => this.pluginRegistry.get(id))
			.filter((p): p is MischiefPlugin => p !== undefined)
			.filter((p) => phases.includes(p.phase));

		return plugins;
	}

	/**
	 * Get enabled plugin IDs based on session mode
	 */
	private getEnabledPlugins(session: Session): string[] {
		switch (session.mode) {
			case "explicit":
				return session.mischief;

			case "random": {
				const probability = session.probability ?? 0.5;
				if (Math.random() > probability) {
					return []; // No mischief this time
				}
				// Pick a random plugin from the enabled set
				const randomIndex = Math.floor(Math.random() * session.mischief.length);
				const selected = session.mischief[randomIndex];
				return selected ? [selected] : [];
			}

			case "shuffled": {
				if (!session.shuffleQueue || session.shuffleQueue.length === 0) {
					return []; // Queue exhausted
				}
				// Pop the next plugin from the queue
				const next = session.shuffleQueue.shift();
				return next ? [next] : [];
			}

			default:
				return [];
		}
	}

	/**
	 * Build context for token-phase plugins
	 */
	private buildTokenContext(
		token: ForgeableToken,
		session: Session,
		plugin: MischiefPlugin,
	): MischiefContext {
		const sessionInfo: MischiefContext["session"] = {
			id: session.id,
			mode: session.mode,
		};
		if (session.name !== undefined) {
			sessionInfo.name = session.name;
		}

		return {
			token: {
				header: token.header,
				claims: token.claims,
				get signature() {
					return token.signature;
				},
				set signature(value: string) {
					token.signature = value;
				},
				getPublicKey: () => token.getPublicKey(),
				sign: (alg: string, key: string | Buffer) => token.sign(alg, key),
			},
			config: this.getPluginConfig(session, plugin.id),
			session: sessionInfo,
		};
	}

	/**
	 * Build context for response-phase plugins
	 */
	private buildResponseContext(session: Session, plugin: MischiefPlugin): MischiefContext {
		const sessionInfo: MischiefContext["session"] = {
			id: session.id,
			mode: session.mode,
		};
		if (session.name !== undefined) {
			sessionInfo.name = session.name;
		}

		return {
			response: {
				status: 200,
				headers: {},
				body: null,
				delay: async (ms: number) => {
					await new Promise((resolve) => setTimeout(resolve, ms));
				},
			},
			config: this.getPluginConfig(session, plugin.id),
			session: sessionInfo,
		};
	}

	/**
	 * Build context for discovery-phase plugins (discovery document and JWKS)
	 */
	private buildDiscoveryContext(
		body: unknown,
		session: Session,
		plugin: MischiefPlugin,
	): MischiefContext {
		const sessionInfo: MischiefContext["session"] = {
			id: session.id,
			mode: session.mode,
		};
		if (session.name !== undefined) {
			sessionInfo.name = session.name;
		}

		return {
			response: {
				status: 200,
				headers: {},
				body,
				delay: async (ms: number) => {
					await new Promise((resolve) => setTimeout(resolve, ms));
				},
			},
			config: this.getPluginConfig(session, plugin.id),
			session: sessionInfo,
		};
	}

	/**
	 * Get plugin-specific config from session
	 */
	private getPluginConfig(_session: Session, _pluginId: string): Record<string, unknown> {
		// TODO: Store and retrieve per-plugin config from session
		return {};
	}

	/**
	 * Record a ledger entry for applied mischief
	 */
	private recordLedgerEntry(
		requestCtx: RequestContext,
		plugin: MischiefPlugin,
		result: MischiefResult,
	): void {
		const spec: LedgerEntry["spec"] = {
			requirement: plugin.spec.description,
			violation: result.mutation,
		};
		if (plugin.spec.rfc !== undefined) {
			spec.rfc = plugin.spec.rfc;
		}
		if (plugin.spec.oidc !== undefined) {
			spec.oidc = plugin.spec.oidc;
		}
		if (plugin.spec.cwe !== undefined) {
			spec.cwe = plugin.spec.cwe;
		}

		const entry: LedgerEntry = {
			id: `entry_${nanoid(8)}`,
			requestId: requestCtx.requestId,
			timestamp: requestCtx.timestamp.toISOString(),
			plugin: {
				id: plugin.id,
				name: plugin.name,
				severity: plugin.severity,
			},
			spec,
			evidence: {
				mutation: result.mutation,
				...result.evidence,
			},
		};

		const sessionId = requestCtx.session.id;
		const entries = this.ledgerEntries.get(sessionId) ?? [];
		entries.push(entry);
		this.ledgerEntries.set(sessionId, entries);

		// Persist to database if callback provided
		if (this.onLedgerEntry) {
			this.onLedgerEntry(sessionId, entry);
		}
	}

	/**
	 * Get ledger entries for a session
	 */
	getLedgerEntries(sessionId: string): LedgerEntry[] {
		return this.ledgerEntries.get(sessionId) ?? [];
	}

	/**
	 * Build a complete ledger for a session
	 */
	buildLedger(session: Session): MischiefLedger {
		const entries = this.getLedgerEntries(session.id);

		const mischiefByPlugin: Record<string, number> = {};
		const mischiefBySeverity: Record<string, number> = {
			critical: 0,
			high: 0,
			medium: 0,
			low: 0,
		};

		for (const entry of entries) {
			mischiefByPlugin[entry.plugin.id] = (mischiefByPlugin[entry.plugin.id] ?? 0) + 1;
			mischiefBySeverity[entry.plugin.severity] =
				(mischiefBySeverity[entry.plugin.severity] ?? 0) + 1;
		}

		const meta: MischiefLedger["meta"] = {
			version: "1.0.0",
			sessionId: session.id,
			mode: session.mode,
			startedAt: session.startedAt.toISOString(),
			lokiVersion: "0.1.0",
		};

		if (session.name !== undefined) {
			meta.sessionName = session.name;
		}
		if (session.endedAt !== undefined) {
			meta.endedAt = session.endedAt.toISOString();
		}

		return {
			meta,
			summary: {
				totalRequests: new Set(entries.map((e) => e.requestId)).size,
				requestsWithMischief: entries.length,
				mischiefByPlugin,
				mischiefBySeverity: mischiefBySeverity as MischiefLedger["summary"]["mischiefBySeverity"],
			},
			entries,
		};
	}

	/**
	 * Clear ledger entries for a session
	 */
	clearLedger(sessionId: string): void {
		this.ledgerEntries.delete(sessionId);
	}
}
