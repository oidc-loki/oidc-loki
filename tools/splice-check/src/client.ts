/**
 * OAuth HTTP client for token endpoint interactions.
 *
 * Supports:
 *   - client_credentials grant (for obtaining initial tokens)
 *   - token exchange grant (RFC 8693)
 *   - client_secret_post and client_secret_basic authentication
 *   - token revocation (RFC 7009)
 *   - token introspection (RFC 7662)
 */

import type { AuthConfig, ClientConfig, TargetConfig } from "./config.js";
import { type AttackResponse, GRANT_TYPE_TOKEN_EXCHANGE } from "./tests/types.js";

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export class OAuthClient {
	private readonly target: TargetConfig;
	private readonly clients: Record<string, ClientConfig>;

	constructor(target: TargetConfig, clients: Record<string, ClientConfig>) {
		this.target = target;
		this.clients = clients;
	}

	/**
	 * Obtain a token via client_credentials grant for the named client.
	 */
	async clientCredentials(clientName: string): Promise<string> {
		const client = this.resolveClient(clientName);
		const params = new URLSearchParams({
			grant_type: client.grant_type ?? "client_credentials",
		});
		if (client.scope) {
			params.set("scope", client.scope);
		}

		const response = await this.post(params, client);
		if (response.status !== 200) {
			throw new OAuthError(
				`client_credentials for "${clientName}" failed: HTTP ${response.status}`,
				response,
			);
		}

		const body = response.body as TokenResponse;
		if (!body.access_token) {
			throw new OAuthError(
				`client_credentials for "${clientName}" returned no access_token`,
				response,
			);
		}

		return body.access_token;
	}

	/**
	 * Perform an RFC 8693 token exchange.
	 *
	 * The caller provides all exchange parameters; this method handles
	 * client authentication and HTTP mechanics.
	 */
	async tokenExchange(params: TokenExchangeParams): Promise<AttackResponse> {
		const client = this.resolveClient(params.clientName ?? "agent-a");
		const body = new URLSearchParams({
			grant_type: GRANT_TYPE_TOKEN_EXCHANGE,
			subject_token: params.subject_token,
			subject_token_type: params.subject_token_type,
		});

		if (params.actor_token !== undefined) {
			body.set("actor_token", params.actor_token);
		}
		if (params.actor_token_type !== undefined) {
			body.set("actor_token_type", params.actor_token_type);
		}
		if (params.audience !== undefined) {
			appendMultiValue(body, "audience", params.audience);
		}
		if (params.resource !== undefined) {
			appendMultiValue(body, "resource", params.resource);
		}
		if (params.scope !== undefined) {
			body.set("scope", params.scope);
		}
		if (params.requested_token_type !== undefined) {
			body.set("requested_token_type", params.requested_token_type);
		}

		return this.post(body, client);
	}

	/**
	 * Perform a raw (unauthenticated) token exchange request.
	 *
	 * Sends exchange parameters WITHOUT any client authentication.
	 * Used by TE-02 to verify the AS requires client auth.
	 */
	async rawTokenExchange(params: URLSearchParams): Promise<AttackResponse> {
		const headers: Record<string, string> = {
			"Content-Type": "application/x-www-form-urlencoded",
			Accept: "application/json",
		};

		const timeout = this.target.timeout ?? 30_000;
		const start = performance.now();
		const response = await fetch(this.target.token_endpoint, {
			method: "POST",
			headers,
			body: params.toString(),
			signal: AbortSignal.timeout(timeout),
		});
		const durationMs = Math.round(performance.now() - start);

		const responseHeaders: Record<string, string> = {};
		response.headers.forEach((value, key) => {
			responseHeaders[key] = value;
		});

		let body: unknown;
		const contentType = response.headers.get("content-type") ?? "";
		if (contentType.includes("application/json")) {
			body = await response.json();
		} else {
			body = await response.text();
		}

		return { status: response.status, body, headers: responseHeaders, durationMs };
	}

	/**
	 * Refresh a token using the refresh_token grant.
	 */
	async refreshToken(refreshToken: string, clientName: string): Promise<AttackResponse> {
		const client = this.resolveClient(clientName);
		const params = new URLSearchParams({
			grant_type: "refresh_token",
			refresh_token: refreshToken,
		});

		return this.post(params, client);
	}

	/**
	 * Revoke a token (RFC 7009).
	 *
	 * Uses the same token endpoint with a /revoke suffix by convention,
	 * or a dedicated revocation_endpoint if configured.
	 */
	async revokeToken(
		token: string,
		clientName: string,
		tokenTypeHint?: string,
	): Promise<AttackResponse> {
		const client = this.resolveClient(clientName);
		const endpoint =
			this.target.revocation_endpoint ?? this.target.token_endpoint.replace(/\/token$/, "/revoke");

		const params = new URLSearchParams({ token });
		if (tokenTypeHint) {
			params.set("token_type_hint", tokenTypeHint);
		}

		return this.postToEndpoint(endpoint, params, client);
	}

	/**
	 * Introspect a token (RFC 7662).
	 */
	async introspectToken(token: string, clientName: string): Promise<AttackResponse> {
		const client = this.resolveClient(clientName);
		const endpoint =
			this.target.introspection_endpoint ??
			this.target.token_endpoint.replace(/\/token$/, "/introspect");

		const params = new URLSearchParams({ token });
		return this.postToEndpoint(endpoint, params, client);
	}

	// -----------------------------------------------------------------------
	// Internal helpers
	// -----------------------------------------------------------------------

	private resolveClient(name: string): ClientConfig {
		const client = this.clients[name];
		if (!client) {
			throw new Error(
				`Unknown client: "${name}". Available: ${Object.keys(this.clients).join(", ")}`,
			);
		}
		return client;
	}

	private async post(params: URLSearchParams, client: ClientConfig): Promise<AttackResponse> {
		return this.postToEndpoint(this.target.token_endpoint, params, client);
	}

	private async postToEndpoint(
		endpoint: string,
		params: URLSearchParams,
		client: ClientConfig,
	): Promise<AttackResponse> {
		const headers: Record<string, string> = {
			"Content-Type": "application/x-www-form-urlencoded",
			Accept: "application/json",
		};

		this.applyClientAuth(params, headers, client, this.target.auth);

		const timeout = this.target.timeout ?? 30_000;
		const start = performance.now();
		const response = await fetch(endpoint, {
			method: "POST",
			headers,
			body: params.toString(),
			signal: AbortSignal.timeout(timeout),
		});
		const durationMs = Math.round(performance.now() - start);

		const responseHeaders: Record<string, string> = {};
		response.headers.forEach((value, key) => {
			responseHeaders[key] = value;
		});

		let body: unknown;
		const contentType = response.headers.get("content-type") ?? "";
		if (contentType.includes("application/json")) {
			body = await response.json();
		} else {
			body = await response.text();
		}

		return {
			status: response.status,
			body,
			headers: responseHeaders,
			durationMs,
		};
	}

	private applyClientAuth(
		params: URLSearchParams,
		headers: Record<string, string>,
		client: ClientConfig,
		auth: AuthConfig,
	): void {
		switch (auth.method) {
			case "client_secret_basic":
				// RFC 6749 Section 2.3.1: URL-encode before base64
				headers.Authorization = `Basic ${btoa(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`)}`;
				break;
			case "client_secret_post":
				params.set("client_id", client.client_id);
				params.set("client_secret", client.client_secret);
				break;
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Append a string or string[] as multiple values for the same key. */
function appendMultiValue(params: URLSearchParams, key: string, value: string | string[]): void {
	if (Array.isArray(value)) {
		for (const v of value) {
			params.append(key, v);
		}
	} else {
		params.set(key, value);
	}
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TokenExchangeParams {
	subject_token: string;
	subject_token_type: string;
	actor_token?: string;
	actor_token_type?: string;
	/** Logical audience for the token (RFC 8693 Section 2.1) */
	audience?: string | string[];
	/** Physical resource URI(s) (RFC 8693 Section 2.1) */
	resource?: string | string[];
	scope?: string;
	requested_token_type?: string;
	/** Which configured client to authenticate as (default: "agent-a") */
	clientName?: string;
}

interface TokenResponse {
	access_token?: string;
	token_type?: string;
	expires_in?: number;
	refresh_token?: string;
	scope?: string;
	issued_token_type?: string;
}

export class OAuthError extends Error {
	public readonly response: AttackResponse;

	constructor(message: string, response: AttackResponse) {
		super(message);
		this.name = "OAuthError";
		this.response = response;
	}
}
