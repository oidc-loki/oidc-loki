/**
 * Provider Adapter - wraps node-oidc-provider
 *
 * Creates a configured OIDC provider instance that Loki can intercept and corrupt.
 */

import Provider, {
	type Configuration,
	type KoaContextWithOIDC,
	type ClientMetadata,
} from "oidc-provider";
import type { ClientConfig, ProviderConfig } from "./types.js";

export interface ProviderAdapterOptions {
	config: ProviderConfig;
	onTokenSign?: (ctx: KoaContextWithOIDC, token: TokenSignContext) => Promise<void>;
}

export interface TokenSignContext {
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
}

/**
 * Creates and configures an oidc-provider instance
 */
export function createProvider(options: ProviderAdapterOptions): Provider {
	const { config } = options;

	const configuration: Configuration = {
		clients: config.clients.map(clientToOidcConfig),

		// Features we need for testing
		features: {
			devInteractions: { enabled: true }, // Simple login UI for testing
			clientCredentials: { enabled: true },
			introspection: { enabled: true },
			revocation: { enabled: true },
			resourceIndicators: {
				enabled: true,
				// Default resource when none specified - required for client_credentials to get JWT
				defaultResource: async (_ctx, _client, _oneOf) => {
					return "https://loki.test/api";
				},
				// Return resource server info with JWT format
				getResourceServerInfo: async (_ctx, _resourceIndicator, _client) => {
					return {
						scope: "openid profile email",
						accessTokenFormat: "jwt" as const,
						accessTokenTTL: 3600,
					};
				},
				// Use the granted resource even when openid scope present
				useGrantedResource: async (_ctx, _model) => {
					return true;
				},
			},
		},

		// Cookie keys (required)
		cookies: {
			keys: ["loki-secret-key-1", "loki-secret-key-2"],
		},

		// PKCE configuration
		pkce: {
			required: () => false, // Don't require PKCE for testing flexibility
		},

		// We don't need custom formats - oidc-provider uses JWT for id_tokens by default
		// Access tokens will be opaque unless we configure otherwise

		// TTL configuration
		ttl: {
			AccessToken: 3600,
			AuthorizationCode: 600,
			IdToken: 3600,
			RefreshToken: 86400,
		},

		// Claims configuration
		claims: {
			openid: ["sub"],
			email: ["email", "email_verified"],
			profile: ["name", "family_name", "given_name"],
		},

		// Simple in-memory adapter for testing
		// In production, you'd use a persistent adapter
		adapter: undefined, // Uses default in-memory adapter

		// Find account by ID (for userinfo endpoint)
		findAccount: async (_ctx: unknown, id: string) => ({
			accountId: id,
			claims: async () => ({
				sub: id,
				email: `${id}@loki.test`,
				email_verified: true,
				name: "Test User",
			}),
		}),

		// Allow insecure requests for local testing
		renderError: async (ctx: { type: string; body: unknown }, out: unknown, _error: unknown) => {
			ctx.type = "application/json";
			ctx.body = out;
		},
	};

	const provider = new Provider(config.issuer, configuration);

	// Disable some security checks for local testing
	// These would normally block http:// issuers
	const originalProxyCheck = provider.proxy;
	provider.proxy = true;

	// Log proxy setting for debugging
	if (originalProxyCheck !== provider.proxy) {
		// Proxy mode enabled
	}

	return provider;
}

/**
 * Convert our ClientConfig to oidc-provider's client format
 */
function clientToOidcConfig(client: ClientConfig): ClientMetadata {
	const grantTypes = client.grant_types ?? ["authorization_code"];

	// Determine response_types based on grant_types
	// client_credentials only -> no response_types needed
	// authorization_code -> code response type
	const needsCodeFlow = grantTypes.includes("authorization_code");
	const responseTypes = needsCodeFlow ? ["code"] : [];

	// redirect_uris required for authorization_code, not for client_credentials only
	const redirectUris =
		client.redirect_uris ?? (needsCodeFlow ? ["https://localhost/callback"] : []);

	return {
		client_id: client.client_id,
		client_secret: client.client_secret,
		redirect_uris: redirectUris,
		grant_types: grantTypes,
		response_types: responseTypes,
		token_endpoint_auth_method: client.client_secret ? "client_secret_basic" : "none",
	};
}

/**
 * Get the callback handler from the provider for use with Node's http server
 */
export function getProviderCallback(provider: Provider): ReturnType<Provider["callback"]> {
	return provider.callback();
}
