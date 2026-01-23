import { describe, expect, it } from "vitest";
import { audienceConfusionPlugin } from "../../src/plugins/built-in/audience-confusion.js";
import { issuerConfusionPlugin } from "../../src/plugins/built-in/issuer-confusion.js";
import { kidManipulationPlugin } from "../../src/plugins/built-in/kid-manipulation.js";
import { nonceBypassPlugin } from "../../src/plugins/built-in/nonce-bypass.js";
import { pkceDowngradePlugin } from "../../src/plugins/built-in/pkce-downgrade.js";
import { stateBypassPlugin } from "../../src/plugins/built-in/state-bypass.js";
import { subjectManipulationPlugin } from "../../src/plugins/built-in/subject-manipulation.js";
import type { MischiefContext } from "../../src/plugins/types.js";

// Helper to create a mock context
function createMockContext(overrides: Partial<MischiefContext> = {}): MischiefContext {
	return {
		sessionId: "sess_test123",
		request: {
			path: "/token",
			method: "POST",
			headers: {},
		},
		token: {
			header: { alg: "RS256", typ: "JWT", kid: "key-1" },
			claims: {
				iss: "https://original-issuer.com",
				sub: "user123",
				aud: "client-app",
				exp: Math.floor(Date.now() / 1000) + 3600,
				iat: Math.floor(Date.now() / 1000),
				nonce: "original-nonce-value",
			},
			raw: "",
		},
		config: {},
		...overrides,
	};
}

describe("Mischief Plugins Unit Tests", () => {
	describe("issuer-confusion", () => {
		it("should have correct metadata", () => {
			expect(issuerConfusionPlugin.id).toBe("issuer-confusion");
			expect(issuerConfusionPlugin.severity).toBe("critical");
			expect(issuerConfusionPlugin.phase).toBe("token-claims");
		});

		it("should replace issuer with evil domain (default mode)", async () => {
			const ctx = createMockContext();
			const result = await issuerConfusionPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.iss).toBe("https://evil-idp.attacker.com");
			expect(result.evidence.mode).toBe("evil");
			expect(result.evidence.originalIssuer).toBe("https://original-issuer.com");
		});

		it("should create similar-looking issuer in similar mode", async () => {
			const ctx = createMockContext({ config: { mode: "similar" } });
			const result = await issuerConfusionPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			// Transforms https://original-issuer.com -> https://auth.original-issuer.co
			expect(ctx.token?.claims.iss).toContain(".co");
			expect(ctx.token?.claims.iss).not.toBe("https://original-issuer.com");
			expect(result.evidence.mode).toBe("similar");
		});

		it("should set empty issuer in empty mode", async () => {
			const ctx = createMockContext({ config: { mode: "empty" } });
			const result = await issuerConfusionPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.iss).toBe("");
			expect(result.evidence.mode).toBe("empty");
		});

		it("should set null issuer in null mode", async () => {
			const ctx = createMockContext({ config: { mode: "null" } });
			const result = await issuerConfusionPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.iss).toBeNull();
			expect(result.evidence.mode).toBe("null");
		});

		it("should not apply without token context", async () => {
			const ctx = createMockContext({ token: undefined });
			const result = await issuerConfusionPlugin.apply(ctx);

			expect(result.applied).toBe(false);
		});
	});

	describe("audience-confusion", () => {
		it("should have correct metadata", () => {
			expect(audienceConfusionPlugin.id).toBe("audience-confusion");
			expect(audienceConfusionPlugin.severity).toBe("critical");
			expect(audienceConfusionPlugin.phase).toBe("token-claims");
		});

		it("should inject malicious audience (default mode)", async () => {
			const ctx = createMockContext();
			const result = await audienceConfusionPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.aud).toContain("https://attacker.com");
			expect(ctx.token?.claims.aud).toContain("client-app");
			expect(result.evidence.mode).toBe("inject");
		});

		it("should replace audience in replace mode", async () => {
			const ctx = createMockContext({ config: { mode: "replace" } });
			const result = await audienceConfusionPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.aud).toBe("https://attacker.com");
			expect(result.evidence.mode).toBe("replace");
		});

		it("should remove audience in remove mode", async () => {
			const ctx = createMockContext({ config: { mode: "remove" } });
			const result = await audienceConfusionPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.aud).toEqual([]);
			expect(result.evidence.mode).toBe("remove");
		});

		it("should set wildcard audience in wildcard mode", async () => {
			const ctx = createMockContext({ config: { mode: "wildcard" } });
			const result = await audienceConfusionPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.aud).toBe("*");
			expect(result.evidence.mode).toBe("wildcard");
		});

		it("should handle array audience in inject mode", async () => {
			const ctx = createMockContext();
			if (ctx.token) {
				ctx.token.claims.aud = ["aud1", "aud2"];
			}
			const result = await audienceConfusionPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.aud).toContain("aud1");
			expect(ctx.token?.claims.aud).toContain("aud2");
			expect(ctx.token?.claims.aud).toContain("https://attacker.com");
		});
	});

	describe("subject-manipulation", () => {
		it("should have correct metadata", () => {
			expect(subjectManipulationPlugin.id).toBe("subject-manipulation");
			expect(subjectManipulationPlugin.severity).toBe("critical");
			expect(subjectManipulationPlugin.phase).toBe("token-claims");
		});

		it("should set admin user (default mode)", async () => {
			const ctx = createMockContext();
			const result = await subjectManipulationPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.sub).toBe("admin");
			expect(result.evidence.mode).toBe("admin");
			expect(result.evidence.originalSubject).toBe("user123");
		});

		it("should use custom target in impersonate mode", async () => {
			const ctx = createMockContext({
				config: { mode: "impersonate", targetUser: "root" },
			});
			const result = await subjectManipulationPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.sub).toBe("root");
			expect(result.evidence.mode).toBe("impersonate");
		});

		it("should set admin identifier in admin mode", async () => {
			const ctx = createMockContext({ config: { mode: "admin" } });
			const result = await subjectManipulationPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.sub).toBe("admin");
			expect(result.evidence.mode).toBe("admin");
		});

		it("should set empty subject in empty mode", async () => {
			const ctx = createMockContext({ config: { mode: "empty" } });
			const result = await subjectManipulationPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.sub).toBe("");
		});

		it("should set numeric subject in numeric mode", async () => {
			const ctx = createMockContext({ config: { mode: "numeric" } });
			const result = await subjectManipulationPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			// Numeric mode returns actual number 1, but it gets cast to string
			expect(ctx.token?.claims.sub).toBe(1);
		});
	});

	describe("kid-manipulation", () => {
		it("should have correct metadata", () => {
			expect(kidManipulationPlugin.id).toBe("kid-manipulation");
			expect(kidManipulationPlugin.severity).toBe("high");
			expect(kidManipulationPlugin.phase).toBe("token-signing");
		});

		it("should set invalid kid (default mode)", async () => {
			const ctx = createMockContext();
			const result = await kidManipulationPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.header.kid).toBe("non-existent-key-id-12345");
			expect(result.evidence.mode).toBe("invalid");
			expect(result.evidence.originalKid).toBe("key-1");
		});

		it("should remove kid in remove mode", async () => {
			const ctx = createMockContext({ config: { mode: "remove" } });
			const result = await kidManipulationPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.header.kid).toBe("");
			expect(result.evidence.mode).toBe("remove");
		});

		it("should set path traversal payload in injection mode", async () => {
			const ctx = createMockContext({ config: { mode: "injection" } });
			const result = await kidManipulationPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.header.kid).toContain("../");
			expect(result.evidence.mode).toBe("injection");
		});

		it("should set SQL injection payload in sql mode", async () => {
			const ctx = createMockContext({ config: { mode: "sql" } });
			const result = await kidManipulationPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.header.kid).toContain("'");
			expect(result.evidence.mode).toBe("sql");
		});
	});

	describe("nonce-bypass", () => {
		it("should have correct metadata", () => {
			expect(nonceBypassPlugin.id).toBe("nonce-bypass");
			expect(nonceBypassPlugin.severity).toBe("high");
			expect(nonceBypassPlugin.phase).toBe("token-claims");
		});

		it("should remove nonce (default mode)", async () => {
			const ctx = createMockContext();
			const result = await nonceBypassPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.nonce).toBeUndefined();
			expect(result.evidence.mode).toBe("remove");
			expect(result.evidence.originalNonce).toBe("original-nonce-value");
		});

		it("should replay previous nonce in replay mode", async () => {
			const ctx = createMockContext({ config: { mode: "replay" } });
			const result = await nonceBypassPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.nonce).toBe("static-predictable-nonce-12345");
			expect(result.evidence.mode).toBe("replay");
		});

		it("should set empty nonce in empty mode", async () => {
			const ctx = createMockContext({ config: { mode: "empty" } });
			const result = await nonceBypassPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.nonce).toBe("");
			expect(result.evidence.mode).toBe("empty");
		});

		it("should mismatch nonce in mismatch mode", async () => {
			const ctx = createMockContext({ config: { mode: "mismatch" } });
			const result = await nonceBypassPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.nonce).not.toBe("original-nonce-value");
			expect(result.evidence.mode).toBe("mismatch");
		});
	});

	describe("state-bypass", () => {
		it("should have correct metadata", () => {
			expect(stateBypassPlugin.id).toBe("state-bypass");
			expect(stateBypassPlugin.severity).toBe("high");
			expect(stateBypassPlugin.phase).toBe("token-claims");
		});

		it("should tamper azp (default mode)", async () => {
			const ctx = createMockContext();
			const result = await stateBypassPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.azp).toBe("malicious-client-id");
			expect(result.evidence.mode).toBe("tamper-azp");
		});

		it("should inject state claim in inject-state mode", async () => {
			const ctx = createMockContext({ config: { mode: "inject-state" } });
			const result = await stateBypassPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.state).toBe("attacker-controlled-state");
			expect(result.evidence.mode).toBe("inject-state");
		});

		it("should add suspicious claims in add-claims mode", async () => {
			const ctx = createMockContext({ config: { mode: "add-claims" } });
			const result = await stateBypassPlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.admin).toBe(true);
			expect(ctx.token?.claims.role).toBe("superuser");
			expect(ctx.token?.claims._debug).toBe(true);
			expect(result.evidence.mode).toBe("add-claims");
		});
	});

	describe("pkce-downgrade", () => {
		it("should have correct metadata", () => {
			expect(pkceDowngradePlugin.id).toBe("pkce-downgrade");
			expect(pkceDowngradePlugin.severity).toBe("high");
			expect(pkceDowngradePlugin.phase).toBe("token-claims");
		});

		it("should weaken auth context (default mode)", async () => {
			const ctx = createMockContext();
			const result = await pkceDowngradePlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.acr).toBe("0");
			expect(ctx.token?.claims.amr).toEqual(["pwd"]);
			expect(result.evidence.mode).toBe("weaken-method");
		});

		it("should inject code_challenge in inject-code-challenge mode", async () => {
			const ctx = createMockContext({
				config: { mode: "inject-code-challenge" },
			});
			const result = await pkceDowngradePlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.code_challenge).toBe("attacker-controlled-challenge");
			expect(ctx.token?.claims.code_challenge_method).toBe("plain");
			expect(result.evidence.mode).toBe("inject-code-challenge");
		});

		it("should add auth_time in add-auth-time mode", async () => {
			const ctx = createMockContext({ config: { mode: "add-auth-time" } });
			const result = await pkceDowngradePlugin.apply(ctx);

			expect(result.applied).toBe(true);
			expect(ctx.token?.claims.auth_time).toBeDefined();
			expect(ctx.token?.claims.auth_time).toBeLessThan(Math.floor(Date.now() / 1000));
			expect(result.evidence.mode).toBe("add-auth-time");
		});
	});
});
