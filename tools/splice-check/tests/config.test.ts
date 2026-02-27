import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "../src/config.js";

describe("loadConfig", () => {
	let tmpDir: string;

	beforeAll(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "splice-check-test-"));
	});

	function writeToml(name: string, content: string): string {
		const path = join(tmpDir, name);
		writeFileSync(path, content);
		return path;
	}

	it("loads a valid config file", () => {
		const path = writeToml(
			"valid.toml",
			`
[target]
token_endpoint = "https://as.example.com/oauth2/token"
jwks_endpoint = "https://as.example.com/oauth2/jwks"
issuer = "https://as.example.com"

[target.auth]
method = "client_secret_post"

[clients.alice]
client_id = "alice-app"
client_secret = "alice-secret"

[clients.agent-a]
client_id = "agent-a"
client_secret = "agent-a-secret"

[clients.agent-n]
client_id = "agent-n"
client_secret = "agent-n-secret"
`,
		);

		const config = loadConfig(path);

		expect(config.target.token_endpoint).toBe("https://as.example.com/oauth2/token");
		expect(config.target.jwks_endpoint).toBe("https://as.example.com/oauth2/jwks");
		expect(config.target.issuer).toBe("https://as.example.com");
		expect(config.target.auth.method).toBe("client_secret_post");
		expect(config.clients.alice?.client_id).toBe("alice-app");
		expect(config.clients["agent-a"]?.client_id).toBe("agent-a");
		expect(config.clients["agent-n"]?.client_id).toBe("agent-n");
	});

	it("applies default auth method (client_secret_post)", () => {
		const path = writeToml(
			"no-auth.toml",
			`
[target]
token_endpoint = "https://as.example.com/token"
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"

[clients.alice]
client_id = "a"
client_secret = "s"
[clients.agent-a]
client_id = "b"
client_secret = "s"
[clients.agent-n]
client_id = "c"
client_secret = "s"
`,
		);

		const config = loadConfig(path);
		expect(config.target.auth.method).toBe("client_secret_post");
	});

	it("applies default output format (table)", () => {
		const path = writeToml(
			"no-output.toml",
			`
[target]
token_endpoint = "https://as.example.com/token"
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"
[clients.alice]
client_id = "a"
client_secret = "s"
[clients.agent-a]
client_id = "b"
client_secret = "s"
[clients.agent-n]
client_id = "c"
client_secret = "s"
`,
		);

		const config = loadConfig(path);
		expect(config.output.format).toBe("table");
		expect(config.output.verbose).toBe(false);
	});

	it("throws on missing target section", () => {
		const path = writeToml(
			"no-target.toml",
			"[clients.alice]\nclient_id = 'a'\nclient_secret = 's'",
		);
		expect(() => loadConfig(path)).toThrow(ConfigError);
		expect(() => loadConfig(path)).toThrow("Missing [target] section");
	});

	it("throws on missing token_endpoint", () => {
		const path = writeToml(
			"no-endpoint.toml",
			`
[target]
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"
[clients.alice]
client_id = "a"
client_secret = "s"
[clients.agent-a]
client_id = "b"
client_secret = "s"
[clients.agent-n]
client_id = "c"
client_secret = "s"
`,
		);
		expect(() => loadConfig(path)).toThrow("Missing target.token_endpoint");
	});

	it("throws on missing required client (alice)", () => {
		const path = writeToml(
			"no-alice.toml",
			`
[target]
token_endpoint = "https://as.example.com/token"
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"
[clients.agent-a]
client_id = "a"
client_secret = "s"
[clients.agent-n]
client_id = "b"
client_secret = "s"
`,
		);
		expect(() => loadConfig(path)).toThrow("Missing required client: [clients.alice]");
	});

	it("throws on missing client_id", () => {
		const path = writeToml(
			"no-id.toml",
			`
[target]
token_endpoint = "https://as.example.com/token"
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"
[clients.alice]
client_secret = "s"
[clients.agent-a]
client_id = "b"
client_secret = "s"
[clients.agent-n]
client_id = "c"
client_secret = "s"
`,
		);
		expect(() => loadConfig(path)).toThrow("missing client_id or client_secret");
	});

	it("throws on invalid auth method", () => {
		const path = writeToml(
			"bad-auth.toml",
			`
[target]
token_endpoint = "https://as.example.com/token"
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"
[target.auth]
method = "private_key_jwt"
[clients.alice]
client_id = "a"
client_secret = "s"
[clients.agent-a]
client_id = "b"
client_secret = "s"
[clients.agent-n]
client_id = "c"
client_secret = "s"
`,
		);
		expect(() => loadConfig(path)).toThrow('Invalid auth method: "private_key_jwt"');
	});

	it("throws on invalid output format", () => {
		const path = writeToml(
			"bad-format.toml",
			`
[target]
token_endpoint = "https://as.example.com/token"
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"
[output]
format = "xml"
[clients.alice]
client_id = "a"
client_secret = "s"
[clients.agent-a]
client_id = "b"
client_secret = "s"
[clients.agent-n]
client_id = "c"
client_secret = "s"
`,
		);
		expect(() => loadConfig(path)).toThrow('Invalid output format: "xml"');
	});

	it("throws on nonexistent file", () => {
		expect(() => loadConfig("/nonexistent/path.toml")).toThrow();
	});

	it("supports client_secret_basic auth method", () => {
		const path = writeToml(
			"basic-auth.toml",
			`
[target]
token_endpoint = "https://as.example.com/token"
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"
[target.auth]
method = "client_secret_basic"
[clients.alice]
client_id = "a"
client_secret = "s"
[clients.agent-a]
client_id = "b"
client_secret = "s"
[clients.agent-n]
client_id = "c"
client_secret = "s"
`,
		);

		const config = loadConfig(path);
		expect(config.target.auth.method).toBe("client_secret_basic");
	});

	it("interpolates environment variables", () => {
		process.env.TEST_SC_SECRET = "env-secret-val";
		const path = writeToml(
			"env-vars.toml",
			`
[target]
token_endpoint = "https://as.example.com/token"
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"
[clients.alice]
client_id = "a"
client_secret = "\${TEST_SC_SECRET}"
[clients.agent-a]
client_id = "b"
client_secret = "s"
[clients.agent-n]
client_id = "c"
client_secret = "s"
`,
		);

		const config = loadConfig(path);
		expect(config.clients.alice?.client_secret).toBe("env-secret-val");
		process.env.TEST_SC_SECRET = undefined;
	});

	it("throws on unset environment variable", () => {
		// Use a random-enough name that won't exist in the environment
		const varName = `_SPLICE_CHECK_TEST_UNSET_${Date.now()}`;
		const path = writeToml(
			"bad-env.toml",
			`
[target]
token_endpoint = "https://as.example.com/token"
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"
[clients.alice]
client_id = "a"
client_secret = "\${${varName}}"
[clients.agent-a]
client_id = "b"
client_secret = "s"
[clients.agent-n]
client_id = "c"
client_secret = "s"
`,
		);

		expect(() => loadConfig(path)).toThrow(varName);
	});

	it("loads optional target fields (revocation_endpoint, timeout)", () => {
		const path = writeToml(
			"optional-target.toml",
			`
[target]
token_endpoint = "https://as.example.com/token"
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"
revocation_endpoint = "https://as.example.com/revoke"
introspection_endpoint = "https://as.example.com/introspect"
timeout = 10000
[clients.alice]
client_id = "a"
client_secret = "s"
[clients.agent-a]
client_id = "b"
client_secret = "s"
[clients.agent-n]
client_id = "c"
client_secret = "s"
`,
		);

		const config = loadConfig(path);
		expect(config.target.revocation_endpoint).toBe("https://as.example.com/revoke");
		expect(config.target.introspection_endpoint).toBe("https://as.example.com/introspect");
		expect(config.target.timeout).toBe(10000);
	});

	it("preserves optional client fields (scope, grant_type)", () => {
		const path = writeToml(
			"optional-fields.toml",
			`
[target]
token_endpoint = "https://as.example.com/token"
jwks_endpoint = "https://as.example.com/jwks"
issuer = "https://as.example.com"
[clients.alice]
client_id = "alice-app"
client_secret = "secret"
grant_type = "authorization_code"
scope = "openid profile email"
[clients.agent-a]
client_id = "a"
client_secret = "s"
[clients.agent-n]
client_id = "b"
client_secret = "s"
`,
		);

		const config = loadConfig(path);
		expect(config.clients.alice?.grant_type).toBe("authorization_code");
		expect(config.clients.alice?.scope).toBe("openid profile email");
	});
});
