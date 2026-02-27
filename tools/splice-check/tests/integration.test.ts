import { type Server, createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OAuthClient } from "../src/client.js";
import type { SpliceCheckConfig } from "../src/config.js";
import { formatResults } from "../src/reporter.js";
import { runTests } from "../src/runner.js";
import { allTests } from "../src/tests/index.js";

// ---------------------------------------------------------------------------
// Mock AS that simulates a VULNERABLE Authorization Server
// (accepts all token exchanges without validation)
// ---------------------------------------------------------------------------

let vulnerableAS: Server;
let vulnerableUrl: string;

// ---------------------------------------------------------------------------
// Mock AS that simulates a SECURE Authorization Server
// (rejects cross-chain exchanges, enforces aud/sub binding)
// ---------------------------------------------------------------------------

let secureAS: Server;
let secureUrl: string;

function createVulnerableAS(): Server {
	return createServer((req, res) => {
		let body = "";
		req.on("data", (chunk) => {
			body += chunk;
		});
		req.on("end", () => {
			res.setHeader("Content-Type", "application/json");
			const params = new URLSearchParams(body);
			const grantType = params.get("grant_type");

			if (grantType === "client_credentials") {
				const clientId = params.get("client_id") ?? "unknown";
				res.writeHead(200);
				res.end(
					JSON.stringify({
						access_token: `token-${clientId}-${Date.now()}`,
						token_type: "Bearer",
						expires_in: 3600,
					}),
				);
			} else if (grantType === "urn:ietf:params:oauth:grant-type:token-exchange") {
				// Vulnerable: accepts ALL exchanges without validation
				res.writeHead(200);
				res.end(
					JSON.stringify({
						access_token: `exchanged-${Date.now()}`,
						token_type: "Bearer",
						issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
						refresh_token: `refresh-${Date.now()}`,
					}),
				);
			} else if (grantType === "refresh_token") {
				res.writeHead(200);
				res.end(JSON.stringify({ access_token: `refreshed-${Date.now()}`, token_type: "Bearer" }));
			} else {
				res.writeHead(400);
				res.end(JSON.stringify({ error: "unsupported_grant_type" }));
			}
		});
	});
}

function createSecureAS(): Server {
	return createServer((req, res) => {
		let body = "";
		req.on("data", (chunk) => {
			body += chunk;
		});
		req.on("end", () => {
			res.setHeader("Content-Type", "application/json");
			const params = new URLSearchParams(body);
			const grantType = params.get("grant_type");
			const clientId = params.get("client_id") ?? "unknown";

			if (req.url === "/oauth2/token") {
				if (grantType === "client_credentials") {
					res.writeHead(200);
					res.end(
						JSON.stringify({
							access_token: `token-${clientId}`,
							token_type: "Bearer",
							expires_in: 3600,
						}),
					);
				} else if (grantType === "urn:ietf:params:oauth:grant-type:token-exchange") {
					const subjectToken = params.get("subject_token") ?? "";
					const actorToken = params.get("actor_token");

					// Secure: reject if actor_token is present and from different chain
					if (actorToken && !subjectToken.includes(clientId)) {
						res.writeHead(400);
						res.end(
							JSON.stringify({
								error: "invalid_grant",
								error_description: "actor_token.sub does not match subject_token.aud",
							}),
						);
					} else {
						res.writeHead(200);
						res.end(
							JSON.stringify({
								access_token: `exchanged-${clientId}`,
								token_type: "Bearer",
								issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
							}),
						);
					}
				} else if (grantType === "refresh_token") {
					res.writeHead(200);
					res.end(JSON.stringify({ access_token: "refreshed", token_type: "Bearer" }));
				} else {
					res.writeHead(400);
					res.end(JSON.stringify({ error: "unsupported_grant_type" }));
				}
			} else if (req.url === "/oauth2/revoke") {
				res.writeHead(200);
				res.end("{}");
			} else if (req.url === "/oauth2/introspect") {
				res.writeHead(200);
				res.end(JSON.stringify({ active: false }));
			} else {
				res.writeHead(404);
				res.end(JSON.stringify({ error: "not_found" }));
			}
		});
	});
}

async function startServer(server: Server): Promise<string> {
	return new Promise<string>((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			const addr = server.address();
			if (addr && typeof addr === "object") {
				resolve(`http://127.0.0.1:${addr.port}`);
			}
		});
	});
}

async function stopServer(server: Server): Promise<void> {
	return new Promise<void>((resolve) => {
		server.close(() => resolve());
	});
}

beforeAll(async () => {
	vulnerableAS = createVulnerableAS();
	secureAS = createSecureAS();
	[vulnerableUrl, secureUrl] = await Promise.all([
		startServer(vulnerableAS),
		startServer(secureAS),
	]);
});

afterAll(async () => {
	await Promise.all([stopServer(vulnerableAS), stopServer(secureAS)]);
});

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

function makeConfig(url: string): SpliceCheckConfig {
	return {
		target: {
			token_endpoint: `${url}/oauth2/token`,
			jwks_endpoint: `${url}/oauth2/jwks`,
			issuer: url,
			auth: { method: "client_secret_post" },
		},
		clients: {
			alice: { client_id: "alice-app", client_secret: "alice-secret", scope: "openid" },
			"agent-a": { client_id: "agent-a", client_secret: "agent-a-secret" },
			"agent-n": { client_id: "agent-n", client_secret: "agent-n-secret" },
		},
		output: { format: "table", verbose: false },
	};
}

describe("Integration: vulnerable AS", () => {
	it("baseline passes (AS accepts valid exchange)", async () => {
		const config = makeConfig(vulnerableUrl);
		const client = new OAuthClient(config.target, config.clients);
		const result = await runTests(allTests.slice(0, 1), config, client);

		expect(result.results[0]?.verdict).toHaveProperty("passed", true);
	});

	it("detects splice vulnerability (basic-splice fails)", async () => {
		const config = makeConfig(vulnerableUrl);
		const client = new OAuthClient(config.target, config.clients);
		const result = await runTests(
			allTests.filter((t) => t.id === "basic-splice"),
			config,
			client,
		);

		const verdict = result.results[0]?.verdict;
		expect(verdict && "passed" in verdict && verdict.passed).toBe(false);
	});

	it("runs all tests and finds failures", async () => {
		const config = makeConfig(vulnerableUrl);
		const client = new OAuthClient(config.target, config.clients);
		const result = await runTests(allTests, config, client);

		expect(result.summary.total).toBe(13);
		expect(result.summary.failed).toBeGreaterThan(0);
	});
});

describe("Integration: secure AS", () => {
	it("baseline passes", async () => {
		const config = makeConfig(secureUrl);
		const client = new OAuthClient(config.target, config.clients);
		const result = await runTests(
			allTests.filter((t) => t.id === "valid-delegation"),
			config,
			client,
		);

		expect(result.results[0]?.verdict).toHaveProperty("passed", true);
	});

	it("basic-splice passes (AS rejects cross-chain)", async () => {
		const config = makeConfig(secureUrl);
		const client = new OAuthClient(config.target, config.clients);
		const result = await runTests(
			allTests.filter((t) => t.id === "basic-splice"),
			config,
			client,
		);

		const verdict = result.results[0]?.verdict;
		expect(verdict && "passed" in verdict && verdict.passed).toBe(true);
	});
});

describe("Integration: output formats", () => {
	it("produces valid JSON output", async () => {
		const config = makeConfig(vulnerableUrl);
		const client = new OAuthClient(config.target, config.clients);
		const result = await runTests(allTests.slice(0, 2), config, client);

		const json = formatResults(result, "json");
		const parsed = JSON.parse(json);
		expect(parsed.results).toHaveLength(2);
		expect(parsed.summary.total).toBe(2);
	});

	it("produces markdown output with failure details", async () => {
		const config = makeConfig(vulnerableUrl);
		const client = new OAuthClient(config.target, config.clients);
		const result = await runTests(
			allTests.filter((t) => t.id === "basic-splice"),
			config,
			client,
		);

		const md = formatResults(result, "markdown");
		expect(md).toContain("# splice-check Report");
		expect(md).toContain("## Failures");
	});
});
