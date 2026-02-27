import { type Server, createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OAuthClient, OAuthError } from "../src/client.js";
import type { ClientConfig, TargetConfig } from "../src/config.js";

// ---------------------------------------------------------------------------
// Mock AS server
// ---------------------------------------------------------------------------

let mockAS: Server;
let baseUrl: string;
const requests: Array<{ path: string; body: string; headers: Record<string, string> }> = [];

function makeTarget(url: string): TargetConfig {
	return {
		token_endpoint: `${url}/oauth2/token`,
		jwks_endpoint: `${url}/oauth2/jwks`,
		issuer: url,
		auth: { method: "client_secret_post" },
	};
}

const testClients: Record<string, ClientConfig> = {
	alice: { client_id: "alice-app", client_secret: "alice-secret", scope: "openid" },
	"agent-a": { client_id: "agent-a", client_secret: "agent-a-secret" },
	"agent-n": { client_id: "agent-n", client_secret: "agent-n-secret" },
};

beforeAll(async () => {
	mockAS = createServer((req, res) => {
		let body = "";
		req.on("data", (chunk) => {
			body += chunk;
		});
		req.on("end", () => {
			const headers: Record<string, string> = {};
			for (const [key, val] of Object.entries(req.headers)) {
				if (typeof val === "string") headers[key] = val;
			}
			requests.push({ path: req.url ?? "", body, headers });

			const params = new URLSearchParams(body);
			const grantType = params.get("grant_type");

			res.setHeader("Content-Type", "application/json");

			if (req.url === "/oauth2/token") {
				if (grantType === "client_credentials") {
					res.writeHead(200);
					res.end(
						JSON.stringify({
							access_token: `mock-token-${params.get("client_id")}`,
							token_type: "Bearer",
							expires_in: 3600,
						}),
					);
				} else if (grantType === "urn:ietf:params:oauth:grant-type:token-exchange") {
					const subjectToken = params.get("subject_token");
					const actorToken = params.get("actor_token");

					// Simulate: reject if subject and actor are from different chains
					if (subjectToken?.includes("alice") && actorToken?.includes("agent-n")) {
						res.writeHead(400);
						res.end(
							JSON.stringify({
								error: "invalid_grant",
								error_description: "Cross-chain splice rejected",
							}),
						);
					} else {
						res.writeHead(200);
						res.end(
							JSON.stringify({
								access_token: "mock-exchanged-token",
								token_type: "Bearer",
								issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
							}),
						);
					}
				} else if (grantType === "refresh_token") {
					res.writeHead(200);
					res.end(JSON.stringify({ access_token: "refreshed-token", token_type: "Bearer" }));
				} else {
					res.writeHead(400);
					res.end(JSON.stringify({ error: "unsupported_grant_type" }));
				}
			} else if (req.url === "/oauth2/revoke") {
				res.writeHead(200);
				res.end("{}");
			} else if (req.url === "/oauth2/introspect") {
				const token = params.get("token");
				res.writeHead(200);
				res.end(JSON.stringify({ active: token !== "revoked-token" }));
			} else {
				res.writeHead(404);
				res.end(JSON.stringify({ error: "not_found" }));
			}
		});
	});

	await new Promise<void>((resolve) => {
		mockAS.listen(0, "127.0.0.1", () => {
			const addr = mockAS.address();
			if (addr && typeof addr === "object") {
				baseUrl = `http://127.0.0.1:${addr.port}`;
			}
			resolve();
		});
	});
});

afterAll(async () => {
	await new Promise<void>((resolve) => {
		mockAS.close(() => resolve());
	});
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("OAuthClient", () => {
	describe("clientCredentials", () => {
		it("obtains an access token for a named client", async () => {
			const client = new OAuthClient(makeTarget(baseUrl), testClients);
			const token = await client.clientCredentials("alice");
			expect(token).toBe("mock-token-alice-app");
		});

		it("throws OAuthError on non-200 response", async () => {
			const badClients: Record<string, ClientConfig> = {
				...testClients,
				alice: { client_id: "alice-app", client_secret: "s", grant_type: "bad_grant" },
			};
			const client = new OAuthClient(makeTarget(baseUrl), badClients);
			await expect(client.clientCredentials("alice")).rejects.toThrow(OAuthError);
		});

		it("throws on unknown client name", async () => {
			const client = new OAuthClient(makeTarget(baseUrl), testClients);
			await expect(client.clientCredentials("nonexistent")).rejects.toThrow(
				'Unknown client: "nonexistent"',
			);
		});
	});

	describe("tokenExchange", () => {
		it("performs a successful token exchange", async () => {
			const client = new OAuthClient(makeTarget(baseUrl), testClients);
			const response = await client.tokenExchange({
				subject_token: "mock-token-agent-a",
				subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
				clientName: "agent-a",
			});
			expect(response.status).toBe(200);
			expect((response.body as Record<string, unknown>).access_token).toBe("mock-exchanged-token");
			expect(response.durationMs).toBeGreaterThanOrEqual(0);
		});

		it("returns 400 for cross-chain splice attempt", async () => {
			const client = new OAuthClient(makeTarget(baseUrl), testClients);
			const response = await client.tokenExchange({
				subject_token: "mock-token-alice-app",
				subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
				actor_token: "mock-token-agent-n",
				actor_token_type: "urn:ietf:params:oauth:token-type:access_token",
				clientName: "agent-n",
			});
			expect(response.status).toBe(400);
			expect((response.body as Record<string, unknown>).error).toBe("invalid_grant");
		});

		it("includes optional parameters when provided", async () => {
			const client = new OAuthClient(makeTarget(baseUrl), testClients);
			requests.length = 0;

			await client.tokenExchange({
				subject_token: "token",
				subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
				audience: "my-audience",
				scope: "openid",
				requested_token_type: "urn:ietf:params:oauth:token-type:jwt",
				clientName: "agent-a",
			});

			const lastRequest = requests[requests.length - 1];
			expect(lastRequest).toBeDefined();
			const params = new URLSearchParams(lastRequest?.body);
			expect(params.get("audience")).toBe("my-audience");
			expect(params.get("scope")).toBe("openid");
			expect(params.get("requested_token_type")).toBe("urn:ietf:params:oauth:token-type:jwt");
		});

		it("defaults clientName to agent-a", async () => {
			const client = new OAuthClient(makeTarget(baseUrl), testClients);
			requests.length = 0;

			await client.tokenExchange({
				subject_token: "token",
				subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
			});

			const lastRequest = requests[requests.length - 1];
			const params = new URLSearchParams(lastRequest?.body);
			expect(params.get("client_id")).toBe("agent-a");
		});
	});

	describe("refreshToken", () => {
		it("refreshes a token", async () => {
			const client = new OAuthClient(makeTarget(baseUrl), testClients);
			const response = await client.refreshToken("refresh-token-123", "agent-a");
			expect(response.status).toBe(200);
			expect((response.body as Record<string, unknown>).access_token).toBe("refreshed-token");
		});
	});

	describe("revokeToken", () => {
		it("revokes a token", async () => {
			const client = new OAuthClient(makeTarget(baseUrl), testClients);
			const response = await client.revokeToken("some-token", "alice", "access_token");
			expect(response.status).toBe(200);
		});
	});

	describe("introspectToken", () => {
		it("introspects an active token", async () => {
			const client = new OAuthClient(makeTarget(baseUrl), testClients);
			const response = await client.introspectToken("active-token", "agent-a");
			expect(response.status).toBe(200);
			expect((response.body as Record<string, unknown>).active).toBe(true);
		});

		it("introspects a revoked token", async () => {
			const client = new OAuthClient(makeTarget(baseUrl), testClients);
			const response = await client.introspectToken("revoked-token", "agent-a");
			expect(response.status).toBe(200);
			expect((response.body as Record<string, unknown>).active).toBe(false);
		});
	});

	describe("client authentication", () => {
		it("uses client_secret_basic when configured", async () => {
			const basicTarget = makeTarget(baseUrl);
			basicTarget.auth.method = "client_secret_basic";

			const client = new OAuthClient(basicTarget, testClients);
			requests.length = 0;

			await client.clientCredentials("alice");

			const lastRequest = requests[requests.length - 1];
			expect(lastRequest?.headers.authorization).toMatch(/^Basic /);

			// Verify base64 decoding
			const encoded = lastRequest?.headers.authorization?.replace("Basic ", "") ?? "";
			const decoded = atob(encoded);
			// RFC 6749 Section 2.3.1: client_id and client_secret are URL-encoded before base64
			expect(decoded).toBe(
				`${encodeURIComponent("alice-app")}:${encodeURIComponent("alice-secret")}`,
			);
		});

		it("uses client_secret_post when configured", async () => {
			const client = new OAuthClient(makeTarget(baseUrl), testClients);
			requests.length = 0;

			await client.clientCredentials("alice");

			const lastRequest = requests[requests.length - 1];
			const params = new URLSearchParams(lastRequest?.body);
			expect(params.get("client_id")).toBe("alice-app");
			expect(params.get("client_secret")).toBe("alice-secret");
			expect(lastRequest?.headers.authorization).toBeUndefined();
		});
	});
});
