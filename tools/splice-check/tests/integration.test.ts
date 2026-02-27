import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OAuthClient } from "../src/client.js";
import type { SpliceCheckConfig } from "../src/config.js";
import { formatResults } from "../src/reporter.js";
import { runTests } from "../src/runner.js";
import { allTests } from "../src/tests/index.js";

// ---------------------------------------------------------------------------
// Shared mock AS utilities
// ---------------------------------------------------------------------------

type MockHandler = (params: URLSearchParams, req: IncomingMessage, res: ServerResponse) => void;

function createMockAS(routes: Record<string, MockHandler>): Server {
	return createServer((req, res) => {
		let body = "";
		req.on("data", (chunk) => {
			body += chunk;
		});
		req.on("end", () => {
			res.setHeader("Content-Type", "application/json");
			const params = new URLSearchParams(body);
			const handler = routes[req.url ?? ""];
			if (handler) {
				handler(params, req, res);
			} else {
				res.writeHead(404);
				res.end(JSON.stringify({ error: "not_found" }));
			}
		});
	});
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
	res.writeHead(status);
	res.end(JSON.stringify(body));
}

// ---------------------------------------------------------------------------
// Mock AS: VULNERABLE (accepts all token exchanges without validation)
// ---------------------------------------------------------------------------

let vulnerableAS: Server;
let vulnerableUrl: string;

function vulnerableTokenHandler(
	params: URLSearchParams,
	_req: IncomingMessage,
	res: ServerResponse,
): void {
	const grantType = params.get("grant_type");
	if (grantType === "client_credentials") {
		const clientId = params.get("client_id") ?? "unknown";
		sendJson(res, 200, {
			access_token: `token-${clientId}-${Date.now()}`,
			token_type: "Bearer",
			expires_in: 3600,
		});
	} else if (grantType === "urn:ietf:params:oauth:grant-type:token-exchange") {
		// Vulnerable: accepts ALL exchanges without validation
		sendJson(res, 200, {
			access_token: `exchanged-${Date.now()}`,
			token_type: "Bearer",
			issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
			refresh_token: `refresh-${Date.now()}`,
		});
	} else if (grantType === "refresh_token") {
		sendJson(res, 200, { access_token: `refreshed-${Date.now()}`, token_type: "Bearer" });
	} else {
		sendJson(res, 400, { error: "unsupported_grant_type" });
	}
}

function createVulnerableAS(): Server {
	return createMockAS({
		"/oauth2/token": vulnerableTokenHandler,
		"/oauth2/revoke": (_params, _req, res) => {
			// Vulnerable: accepts revocation but doesn't actually invalidate anything
			sendJson(res, 200, {});
		},
		"/oauth2/introspect": (_params, _req, res) => {
			// Vulnerable: always says tokens are active (never propagates revocation)
			sendJson(res, 200, { active: true });
		},
	});
}

// ---------------------------------------------------------------------------
// Mock AS: SECURE (rejects cross-chain exchanges, enforces aud/sub binding)
// ---------------------------------------------------------------------------

let secureAS: Server;
let secureUrl: string;

function secureTokenHandler(
	params: URLSearchParams,
	_req: IncomingMessage,
	res: ServerResponse,
): void {
	const grantType = params.get("grant_type");
	const clientId = params.get("client_id") ?? "unknown";

	if (grantType === "client_credentials") {
		sendJson(res, 200, {
			access_token: `token-${clientId}`,
			token_type: "Bearer",
			expires_in: 3600,
		});
	} else if (grantType === "urn:ietf:params:oauth:grant-type:token-exchange") {
		secureExchangeHandler(params, clientId, res);
	} else if (grantType === "refresh_token") {
		sendJson(res, 200, { access_token: "refreshed", token_type: "Bearer" });
	} else {
		sendJson(res, 400, { error: "unsupported_grant_type" });
	}
}

function secureExchangeHandler(
	params: URLSearchParams,
	clientId: string,
	res: ServerResponse,
): void {
	const subjectToken = params.get("subject_token") ?? "";
	const actorToken = params.get("actor_token");

	// Secure: reject if actor_token is present and from different chain
	if (actorToken && !subjectToken.includes(clientId)) {
		sendJson(res, 400, {
			error: "invalid_grant",
			error_description: "actor_token.sub does not match subject_token.aud",
		});
	} else {
		sendJson(res, 200, {
			access_token: `exchanged-${clientId}`,
			token_type: "Bearer",
			issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
		});
	}
}

function createSecureAS(): Server {
	return createMockAS({
		"/oauth2/token": secureTokenHandler,
		"/oauth2/revoke": (_params, _req, res) => {
			sendJson(res, 200, {});
		},
		"/oauth2/introspect": (_params, _req, res) => {
			sendJson(res, 200, { active: false });
		},
	});
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

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
			revocation_endpoint: `${url}/oauth2/revoke`,
			introspection_endpoint: `${url}/oauth2/introspect`,
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
		const result = await runTests(
			allTests.filter((t) => t.id === "valid-delegation"),
			config,
			client,
		);

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

		expect(result.results[0]?.verdict).toHaveProperty("passed", false);
	});

	it("runs all tests and detects specific vulnerabilities", async () => {
		const config = makeConfig(vulnerableUrl);
		const client = new OAuthClient(config.target, config.clients);
		const result = await runTests(allTests, config, client);

		expect(result.summary.total).toBe(18);

		// Baseline should pass (vulnerable AS still accepts valid exchanges)
		const baseline = result.results.find((r) => r.test.id === "valid-delegation");
		expect(baseline?.verdict).toHaveProperty("passed", true);

		// Core splice attacks should detect vulnerabilities (fail = vulnerability detected)
		const basicSpliceResult = result.results.find((r) => r.test.id === "basic-splice");
		expect(basicSpliceResult?.verdict).toHaveProperty("passed", false);

		// Verify there are multiple detected vulnerabilities
		expect(result.summary.failed).toBeGreaterThanOrEqual(3);

		// Verify every test completed (no undefined verdicts)
		for (const r of result.results) {
			expect(r.verdict).toBeDefined();
		}
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

		expect(result.results[0]?.verdict).toHaveProperty("passed", true);
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
