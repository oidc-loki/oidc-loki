/**
 * Core Loki class - the main entry point for library mode
 */

import { existsSync, mkdirSync } from "node:fs";
import { type IncomingMessage, type Server, ServerResponse, createServer } from "node:http";
import { dirname } from "node:path";
import type { Hono } from "hono";
import * as jose from "jose";
import { nanoid } from "nanoid";
import type Provider from "oidc-provider";
import { createAdminApi } from "../admin/routes.js";
import type { MischiefLedger } from "../ledger/types.js";
import { LokiDatabase } from "../persistence/database.js";
import { PluginRegistry } from "../plugins/registry.js";
import {
	MischiefEngine,
	type MischiefEngineOptions,
	type RequestContext,
} from "./mischief-engine.js";
import { createProvider } from "./provider-adapter.js";
import { DEFAULT_CONFIG, type LokiConfig, type Session, type SessionConfig } from "./types.js";

export class Loki {
	private readonly config: Required<LokiConfig>;
	private server: Server | null = null;
	private provider: Provider | null = null;
	private mischiefEngine: MischiefEngine | null = null;
	private database: LokiDatabase | null = null;
	private adminApi: Hono | null = null;
	private readonly sessions = new Map<string, Session>();
	private readonly pluginRegistry: PluginRegistry;
	private jwksCache: string | null = null;

	/** The issuer URL for this Loki instance */
	public readonly issuer: string;

	constructor(config: LokiConfig) {
		this.config = this.mergeConfig(config);
		this.issuer = this.config.provider.issuer;
		this.pluginRegistry = new PluginRegistry(this.config.plugins);
	}

	private mergeConfig(config: LokiConfig): Required<LokiConfig> {
		return {
			server: { ...DEFAULT_CONFIG.server, ...config.server },
			provider: config.provider,
			mischief: { ...DEFAULT_CONFIG.mischief, ...config.mischief },
			plugins: { ...DEFAULT_CONFIG.plugins, ...config.plugins },
			ledger: { ...DEFAULT_CONFIG.ledger, ...config.ledger },
			persistence: { ...DEFAULT_CONFIG.persistence, ...config.persistence },
		};
	}

	/**
	 * Start the Loki server
	 */
	async start(): Promise<void> {
		if (this.server) {
			throw new Error("Loki is already running");
		}

		// Initialize database if persistence is enabled
		if (this.config.persistence.enabled) {
			const dbPath = this.config.persistence.path;
			const dbDir = dirname(dbPath);
			if (!existsSync(dbDir)) {
				mkdirSync(dbDir, { recursive: true });
			}
			this.database = new LokiDatabase({ path: dbPath });

			// Load existing sessions from database
			const storedSessions = this.database.loadAllSessions();
			for (const session of storedSessions) {
				this.sessions.set(session.id, session);
			}
		}

		// Load plugins
		await this.pluginRegistry.loadBuiltIn();
		await this.pluginRegistry.discoverCustom();

		// Create OIDC provider
		this.provider = createProvider({ config: this.config.provider });
		const providerCallback = this.provider.callback();

		// Initialize mischief engine with persistence callback
		const engineOptions: MischiefEngineOptions = {
			pluginRegistry: this.pluginRegistry,
			getPublicKey: async () => this.getPublicKeyPem(),
		};
		if (this.database) {
			const db = this.database;
			engineOptions.onLedgerEntry = (sessionId, entry) => db.saveLedgerEntry(sessionId, entry);
		}
		this.mischiefEngine = new MischiefEngine(engineOptions);

		// Initialize admin API
		this.adminApi = createAdminApi({
			getIssuer: () => this.issuer,
			getPluginCount: () => this.pluginRegistry.count,
			getPluginRegistry: () => this.pluginRegistry,
			listSessions: () => this.listSessions(),
			createSession: (config) => this.createSession(config),
			getSession: (id) => this.getSession(id),
			deleteSession: (id) => this.deleteSession(id),
			purgeSessions: () => this.purgeSessions(),
		});

		// Create HTTP server that routes to admin API or OIDC provider
		this.server = createServer((req: IncomingMessage, res: ServerResponse) => {
			const url = req.url ?? "/";

			// Health check
			if (url === "/health") {
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(
					JSON.stringify({
						status: "ok",
						issuer: this.issuer,
						plugins: this.pluginRegistry.count,
					}),
				);
				return;
			}

			// Admin API routes
			if (url.startsWith("/admin")) {
				this.handleAdminRequest(req, res, url).catch((err) => {
					res.writeHead(500, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ error: "Internal server error", message: String(err) }));
				});
				return;
			}

			// Get session from header if present
			const sessionId = req.headers["x-loki-session"] as string | undefined;
			const session = sessionId ? this.sessions.get(sessionId) : undefined;

			// If this is a token endpoint and we have an active session, intercept
			if (session && (url === "/token" || url.startsWith("/token?"))) {
				this.handleTokenRequest(req, res, session, providerCallback);
				return;
			}

			// If this is a discovery endpoint and we have an active session, intercept
			if (
				session &&
				(url === "/.well-known/openid-configuration" ||
					url.startsWith("/.well-known/openid-configuration?"))
			) {
				this.handleDiscoveryRequest(req, res, session, providerCallback, "discovery");
				return;
			}

			// If this is a JWKS endpoint and we have an active session, intercept
			if (
				session &&
				(url === "/jwks" ||
					url.startsWith("/jwks?") ||
					url === "/.well-known/jwks.json" ||
					url.startsWith("/.well-known/jwks.json?"))
			) {
				this.handleDiscoveryRequest(req, res, session, providerCallback, "jwks");
				return;
			}

			// All other routes go to OIDC provider directly
			providerCallback(req, res);
		});

		const { port, host } = this.config.server;
		await new Promise<void>((resolve) => {
			this.server?.listen(port, host, () => resolve());
		});
	}

	/**
	 * Handle token endpoint with mischief interception
	 *
	 * We intercept by monkey-patching res.write/res.end to capture the response,
	 * apply mischief, then write the modified response.
	 */
	private handleTokenRequest(
		req: IncomingMessage,
		res: ServerResponse,
		session: Session,
		providerCallback: ReturnType<Provider["callback"]>,
	): void {
		const chunks: Buffer[] = [];
		let statusCode = 200;
		let headers: Record<string, string | string[] | number | undefined> = {};

		// Capture the status code
		const originalWriteHead = res.writeHead.bind(res);
		// biome-ignore lint/suspicious/noExplicitAny: complex overloaded function
		(res as any).writeHead = (code: number, ...args: any[]) => {
			statusCode = code;
			// Extract headers if provided
			if (args.length > 0 && typeof args[args.length - 1] === "object") {
				headers = args[args.length - 1];
			}
			// Don't call originalWriteHead yet - we'll do it after mischief
			return res;
		};

		// Capture setHeader calls
		const capturedHeaders: Record<string, string | string[]> = {};
		// biome-ignore lint/suspicious/noExplicitAny: complex overloaded function
		(res as any).setHeader = (name: string, value: any) => {
			capturedHeaders[name.toLowerCase()] = value;
			return res;
		};

		// Capture writes - don't write yet, just buffer
		// biome-ignore lint/suspicious/noExplicitAny: complex overloaded function
		(res as any).write = (chunk: any, _encoding?: any, _cb?: any) => {
			if (chunk) {
				chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
			}
			return true;
		};

		// Intercept end - this is where we apply mischief and write everything
		// biome-ignore lint/suspicious/noExplicitAny: complex overloaded function
		(res as any).end = (chunk?: any, _encoding?: any, _cb?: any) => {
			if (chunk && typeof chunk !== "function") {
				chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
			}

			const body = Buffer.concat(chunks).toString();

			// Apply mischief asynchronously then complete the response
			this.applyMischiefToTokenResponse(body, session, req.url ?? "/token")
				.then((modifiedBody) => {
					// Merge headers
					const finalHeaders = { ...capturedHeaders, ...headers };
					// Update content-length for modified body
					finalHeaders["content-length"] = Buffer.byteLength(modifiedBody);

					// Now actually write the response
					originalWriteHead(statusCode, finalHeaders);
					res.end = ServerResponse.prototype.end.bind(res);
					res.end(modifiedBody);
				})
				.catch(() => {
					// On error, send original body
					const finalHeaders = { ...capturedHeaders, ...headers };
					originalWriteHead(statusCode, finalHeaders);
					res.end = ServerResponse.prototype.end.bind(res);
					res.end(body);
				});
		};

		providerCallback(req, res);
	}

	/**
	 * Apply mischief to a token endpoint response
	 */
	private async applyMischiefToTokenResponse(
		body: string,
		session: Session,
		endpoint: string,
	): Promise<string> {
		if (!this.mischiefEngine) {
			return body;
		}

		// Try to parse as JSON
		let response: Record<string, unknown>;
		try {
			response = JSON.parse(body);
		} catch {
			// Not JSON, return as-is
			return body;
		}

		// Check if this is a token response
		const accessToken = response.access_token as string | undefined;
		const idToken = response.id_token as string | undefined;

		if (!accessToken && !idToken) {
			// Not a token response
			return body;
		}

		const requestCtx: RequestContext = {
			requestId: `req_${nanoid(8)}`,
			session,
			endpoint,
			method: "POST",
			timestamp: new Date(),
		};

		// Apply mischief to access_token if present and looks like JWT
		if (accessToken?.includes(".")) {
			const result = await this.mischiefEngine.applyToToken(accessToken, requestCtx);
			if (result.applications.length > 0) {
				response.access_token = result.token;
			}
		}

		// Apply mischief to id_token if present
		if (idToken?.includes(".")) {
			const result = await this.mischiefEngine.applyToToken(idToken, requestCtx);
			if (result.applications.length > 0) {
				response.id_token = result.token;
			}
		}

		// Apply response-phase mischief (like latency injection)
		await this.mischiefEngine.applyToResponse(requestCtx);

		return JSON.stringify(response);
	}

	/**
	 * Handle discovery/JWKS endpoint with mischief interception
	 */
	private handleDiscoveryRequest(
		req: IncomingMessage,
		res: ServerResponse,
		session: Session,
		providerCallback: ReturnType<Provider["callback"]>,
		endpointType: "discovery" | "jwks",
	): void {
		const chunks: Buffer[] = [];
		let statusCode = 200;
		let headers: Record<string, string | string[] | number | undefined> = {};

		// Capture the status code
		const originalWriteHead = res.writeHead.bind(res);
		// biome-ignore lint/suspicious/noExplicitAny: complex overloaded function
		(res as any).writeHead = (code: number, ...args: any[]) => {
			statusCode = code;
			if (args.length > 0 && typeof args[args.length - 1] === "object") {
				headers = args[args.length - 1];
			}
			return res;
		};

		// Capture setHeader calls
		const capturedHeaders: Record<string, string | string[]> = {};
		// biome-ignore lint/suspicious/noExplicitAny: complex overloaded function
		(res as any).setHeader = (name: string, value: any) => {
			capturedHeaders[name.toLowerCase()] = value;
			return res;
		};

		// Capture writes
		// biome-ignore lint/suspicious/noExplicitAny: complex overloaded function
		(res as any).write = (chunk: any, _encoding?: any, _cb?: any) => {
			if (chunk) {
				chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
			}
			return true;
		};

		// Intercept end
		// biome-ignore lint/suspicious/noExplicitAny: complex overloaded function
		(res as any).end = (chunk?: any, _encoding?: any, _cb?: any) => {
			if (chunk && typeof chunk !== "function") {
				chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
			}

			const body = Buffer.concat(chunks).toString();

			// Apply mischief asynchronously
			this.applyMischiefToDiscoveryResponse(body, session, req.url ?? "/", endpointType)
				.then((modifiedBody) => {
					const finalHeaders = { ...capturedHeaders, ...headers };
					finalHeaders["content-length"] = Buffer.byteLength(modifiedBody);

					originalWriteHead(statusCode, finalHeaders);
					res.end = ServerResponse.prototype.end.bind(res);
					res.end(modifiedBody);
				})
				.catch(() => {
					const finalHeaders = { ...capturedHeaders, ...headers };
					originalWriteHead(statusCode, finalHeaders);
					res.end = ServerResponse.prototype.end.bind(res);
					res.end(body);
				});
		};

		providerCallback(req, res);
	}

	/**
	 * Apply mischief to a discovery/JWKS endpoint response
	 */
	private async applyMischiefToDiscoveryResponse(
		body: string,
		session: Session,
		endpoint: string,
		_endpointType: "discovery" | "jwks",
	): Promise<string> {
		if (!this.mischiefEngine) {
			return body;
		}

		// Try to parse as JSON
		let response: unknown;
		try {
			response = JSON.parse(body);
		} catch {
			return body;
		}

		const requestCtx: RequestContext = {
			requestId: `req_${nanoid(8)}`,
			session,
			endpoint,
			method: "GET",
			timestamp: new Date(),
		};

		// Apply discovery-phase mischief
		const result = await this.mischiefEngine.applyToDiscovery(response, requestCtx);

		if (result.applications.length > 0) {
			return JSON.stringify(result.body);
		}

		return body;
	}

	/**
	 * Get the public key PEM from the JWKS endpoint
	 *
	 * Follows RFC 7517 (JSON Web Key) for JWK parsing and
	 * exports to SPKI format per RFC 5280.
	 */
	private async getPublicKeyPem(): Promise<string> {
		if (this.jwksCache) {
			return this.jwksCache;
		}

		// Fetch from our own JWKS endpoint (RFC 7517 Section 5)
		try {
			const response = await fetch(`${this.issuer}/jwks`);
			const jwks = (await response.json()) as jose.JSONWebKeySet;

			// Get the first signing key
			const jwk = jwks.keys.find((k) => k.use === "sig" || !k.use);
			if (!jwk) {
				return "";
			}

			// Import JWK and export to SPKI PEM format (RFC 7517 -> RFC 5280)
			const keyLike = await jose.importJWK(jwk, jwk.alg);
			const spkiPem = await jose.exportSPKI(keyLike as jose.KeyLike);

			this.jwksCache = spkiPem;
			return this.jwksCache;
		} catch {
			// Failed to fetch or parse JWKS
		}

		return "";
	}

	/**
	 * Handle admin API requests via Hono
	 *
	 * Converts Node.js IncomingMessage to Web Request, routes through Hono,
	 * then converts Web Response back to ServerResponse.
	 */
	private async handleAdminRequest(
		req: IncomingMessage,
		res: ServerResponse,
		url: string,
	): Promise<void> {
		if (!this.adminApi) {
			res.writeHead(500, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ error: "Admin API not initialized" }));
			return;
		}

		// Build the full URL for Hono
		const path = url.replace("/admin", "") || "/";
		const fullUrl = `http://localhost${path}`;

		// Collect request body
		const chunks: Buffer[] = [];
		for await (const chunk of req) {
			chunks.push(chunk as Buffer);
		}
		const body = Buffer.concat(chunks);

		// Create Web Request
		const method = req.method ?? "GET";
		const webRequest = new Request(fullUrl, {
			method,
			headers: req.headers as Record<string, string>,
			body: body.length > 0 && method !== "GET" && method !== "HEAD" ? body : null,
		});

		// Route through Hono
		const webResponse = await this.adminApi.fetch(webRequest);

		// Write response
		res.writeHead(webResponse.status, Object.fromEntries(webResponse.headers.entries()));
		const responseBody = await webResponse.text();
		res.end(responseBody);
	}

	/**
	 * Stop the Loki server
	 */
	async stop(): Promise<void> {
		if (!this.server) {
			return;
		}

		await new Promise<void>((resolve, reject) => {
			this.server?.close((err) => {
				if (err) reject(err);
				else resolve();
			});
		});

		this.server = null;

		// Close database connection
		if (this.database) {
			this.database.close();
			this.database = null;
		}
	}

	/**
	 * Check if Loki is running
	 */
	get isRunning(): boolean {
		return this.server !== null;
	}

	/**
	 * Get the server address
	 */
	get address(): string {
		return `http://${this.config.server.host}:${this.config.server.port}`;
	}

	/**
	 * Create a new test session
	 */
	createSession(config?: Partial<SessionConfig>): SessionHandle {
		const session: Session = {
			id: `sess_${nanoid(12)}`,
			mode: config?.mode ?? "explicit",
			mischief: config?.mischief ?? [],
			startedAt: new Date(),
		};

		// Only set optional properties if they have values
		if (config?.name !== undefined) {
			session.name = config.name;
		}
		if (config?.probability !== undefined) {
			session.probability = config.probability;
		}
		if (config?.mode === "shuffled") {
			session.shuffleQueue = this.shuffleArray([...(config.mischief ?? [])]);
		}

		this.sessions.set(session.id, session);

		// Persist to database
		if (this.database) {
			this.database.saveSession(session);
		}

		return new SessionHandle(session, this);
	}

	/**
	 * Get an existing session by ID
	 */
	getSession(id: string): SessionHandle | undefined {
		const session = this.sessions.get(id);
		return session ? new SessionHandle(session, this) : undefined;
	}

	/**
	 * End a session
	 */
	endSession(id: string): void {
		const session = this.sessions.get(id);
		if (session) {
			session.endedAt = new Date();
			// Persist the update
			if (this.database) {
				this.database.saveSession(session);
			}
		}
	}

	/**
	 * Delete a session
	 */
	deleteSession(id: string): boolean {
		const deleted = this.sessions.delete(id);
		if (deleted && this.database) {
			this.database.deleteSession(id);
		}
		return deleted;
	}

	/**
	 * Get all sessions
	 */
	listSessions(): Session[] {
		return Array.from(this.sessions.values());
	}

	/**
	 * Purge all sessions
	 */
	purgeSessions(): void {
		this.sessions.clear();
		if (this.database) {
			this.database.purgeAll();
		}
	}

	/**
	 * Get the plugin registry
	 */
	get plugins(): PluginRegistry {
		return this.pluginRegistry;
	}

	/**
	 * Register a plugin programmatically
	 */
	register(plugin: Parameters<PluginRegistry["register"]>[0]): void {
		this.pluginRegistry.register(plugin);
	}

	/**
	 * Get the mischief engine (for ledger access)
	 */
	get engine(): MischiefEngine | null {
		return this.mischiefEngine;
	}

	private shuffleArray<T>(array: T[]): T[] {
		const result = [...array];
		for (let i = result.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			// biome-ignore lint/style/noNonNullAssertion: indices are always within bounds in Fisher-Yates shuffle
			[result[i], result[j]] = [result[j]!, result[i]!];
		}
		return result;
	}
}

/**
 * Handle for interacting with a session
 */
export class SessionHandle {
	constructor(
		private readonly session: Session,
		private readonly loki: Loki,
	) {}

	get id(): string {
		return this.session.id;
	}

	get mode(): Session["mode"] {
		return this.session.mode;
	}

	get isEnded(): boolean {
		return this.session.endedAt !== undefined;
	}

	/**
	 * Enable a mischief plugin for this session (explicit mode)
	 */
	enable(pluginId: string, _config?: Record<string, unknown>): void {
		if (this.session.mode !== "explicit") {
			throw new Error(`Cannot enable plugins in ${this.session.mode} mode`);
		}
		if (!this.session.mischief.includes(pluginId)) {
			this.session.mischief.push(pluginId);
		}
		// TODO: Store _config for the plugin
	}

	/**
	 * Disable a mischief plugin for this session
	 */
	disable(pluginId: string): void {
		const index = this.session.mischief.indexOf(pluginId);
		if (index >= 0) {
			this.session.mischief.splice(index, 1);
		}
	}

	/**
	 * Get the mischief ledger for this session
	 */
	getLedger(): MischiefLedger {
		const engine = this.loki.engine;
		if (engine) {
			return engine.buildLedger(this.session);
		}

		// Fallback if engine not initialized
		const meta: MischiefLedger["meta"] = {
			version: "1.0.0",
			sessionId: this.session.id,
			mode: this.session.mode,
			startedAt: this.session.startedAt.toISOString(),
			lokiVersion: "0.1.0",
		};

		if (this.session.name !== undefined) {
			meta.sessionName = this.session.name;
		}
		if (this.session.endedAt !== undefined) {
			meta.endedAt = this.session.endedAt.toISOString();
		}

		return {
			meta,
			summary: {
				totalRequests: 0,
				requestsWithMischief: 0,
				mischiefByPlugin: {},
				mischiefBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
			},
			entries: [],
		};
	}

	/**
	 * End this session
	 */
	end(): void {
		this.loki.endSession(this.session.id);
	}
}
