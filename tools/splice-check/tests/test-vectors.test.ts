import { describe, expect, it } from "vitest";
import { actorClientMismatch } from "../src/tests/actor-client-mismatch.js";
import { audSubBinding } from "../src/tests/aud-sub-binding.js";
import { basicSplice } from "../src/tests/basic-splice.js";
import {
	classifyResponse,
	describeResponse,
	isInconclusive,
	isSecurityRejection,
	jsonBody,
	requireJsonBody,
} from "../src/tests/classify.js";
import { delegationImpersonationConfusion } from "../src/tests/delegation-impersonation-confusion.js";
import { redactTokens, requireToken } from "../src/tests/helpers.js";
import { mayActEnforcement } from "../src/tests/may-act-enforcement.js";
import { missingAud } from "../src/tests/missing-aud.js";
import { multiAudience } from "../src/tests/multi-audience.js";
import { refreshBypass } from "../src/tests/refresh-bypass.js";
import { revocationPropagation } from "../src/tests/revocation-propagation.js";
import { scopeEscalation } from "../src/tests/scope-escalation.js";
import { subjectActorSwap } from "../src/tests/subject-actor-swap.js";
import type { AttackResponse, SetupResult } from "../src/tests/types.js";
import { upstreamSplice } from "../src/tests/upstream-splice.js";
import { validDelegation } from "../src/tests/valid-delegation.js";

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function makeResponse(status: number, body: unknown = {}): AttackResponse {
	return { status, body, headers: {}, durationMs: 10 };
}

const emptySetup: SetupResult = { tokens: {} };

// ---------------------------------------------------------------------------
// classify.ts
// ---------------------------------------------------------------------------

describe("classifyResponse", () => {
	it("classifies 200 as success", () => {
		expect(classifyResponse(makeResponse(200))).toBe("success");
	});

	it("classifies 400 with invalid_grant as security_rejection", () => {
		expect(classifyResponse(makeResponse(400, { error: "invalid_grant" }))).toBe(
			"security_rejection",
		);
	});

	it("classifies 400 with invalid_client as auth_error", () => {
		expect(classifyResponse(makeResponse(400, { error: "invalid_client" }))).toBe("auth_error");
	});

	it("classifies 400 with no error code as security_rejection (default)", () => {
		expect(classifyResponse(makeResponse(400, {}))).toBe("security_rejection");
	});

	it("classifies 401 as auth_error", () => {
		expect(classifyResponse(makeResponse(401))).toBe("auth_error");
	});

	it("classifies 403 as security_rejection", () => {
		expect(classifyResponse(makeResponse(403))).toBe("security_rejection");
	});

	it("classifies 429 as rate_limit", () => {
		expect(classifyResponse(makeResponse(429))).toBe("rate_limit");
	});

	it("classifies 500 as server_error", () => {
		expect(classifyResponse(makeResponse(500))).toBe("server_error");
	});

	it("classifies 302 as unknown", () => {
		expect(classifyResponse(makeResponse(302))).toBe("unknown");
	});
});

describe("isSecurityRejection", () => {
	it("returns true for 400 invalid_grant", () => {
		expect(isSecurityRejection(makeResponse(400, { error: "invalid_grant" }))).toBe(true);
	});

	it("returns false for 401", () => {
		expect(isSecurityRejection(makeResponse(401))).toBe(false);
	});

	it("returns false for 200", () => {
		expect(isSecurityRejection(makeResponse(200))).toBe(false);
	});

	it("returns false for 429", () => {
		expect(isSecurityRejection(makeResponse(429))).toBe(false);
	});
});

describe("isInconclusive", () => {
	it("returns true for auth_error", () => {
		expect(isInconclusive(makeResponse(401))).toBe(true);
	});

	it("returns true for rate_limit", () => {
		expect(isInconclusive(makeResponse(429))).toBe(true);
	});

	it("returns true for server_error", () => {
		expect(isInconclusive(makeResponse(500))).toBe(true);
	});

	it("returns false for security_rejection", () => {
		expect(isInconclusive(makeResponse(400))).toBe(false);
	});

	it("returns false for success", () => {
		expect(isInconclusive(makeResponse(200))).toBe(false);
	});
});

describe("jsonBody", () => {
	it("returns object body", () => {
		expect(jsonBody(makeResponse(200, { key: "val" }))).toEqual({ key: "val" });
	});

	it("returns undefined for string body", () => {
		expect(jsonBody(makeResponse(200, "text"))).toBeUndefined();
	});

	it("returns undefined for null body", () => {
		expect(jsonBody(makeResponse(200, null))).toBeUndefined();
	});
});

describe("requireJsonBody", () => {
	it("returns object body", () => {
		expect(requireJsonBody(makeResponse(200, { key: "val" }))).toEqual({ key: "val" });
	});

	it("throws for string body", () => {
		expect(() => requireJsonBody(makeResponse(200, "text"))).toThrow("Expected JSON object body");
	});
});

describe("describeResponse", () => {
	it("describes success", () => {
		expect(describeResponse(makeResponse(200))).toBe("HTTP 200 success");
	});

	it("describes security rejection with error code", () => {
		expect(describeResponse(makeResponse(400, { error: "invalid_grant" }))).toBe(
			"HTTP 400 security rejection (invalid_grant)",
		);
	});

	it("describes auth error", () => {
		expect(describeResponse(makeResponse(401))).toBe("HTTP 401 auth error");
	});

	it("describes rate limit", () => {
		expect(describeResponse(makeResponse(429))).toBe("HTTP 429 rate limited");
	});
});

// ---------------------------------------------------------------------------
// Test vector verify() logic — unit tests for each test's judgment
// ---------------------------------------------------------------------------

describe("valid-delegation verify", () => {
	it("passes on 200 with access_token", () => {
		const verdict = validDelegation.verify(makeResponse(200, { access_token: "tok" }), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails on 200 without access_token", () => {
		const verdict = validDelegation.verify(makeResponse(200, {}), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("fails on 400", () => {
		const verdict = validDelegation.verify(
			makeResponse(400, { error: "invalid_request" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});
});

describe("basic-splice verify", () => {
	it("passes when AS issues security rejection (400)", () => {
		const verdict = basicSplice.verify(makeResponse(400, { error: "invalid_grant" }), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("passes when AS rejects with 403", () => {
		const verdict = basicSplice.verify(makeResponse(403), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("skips on auth error (401)", () => {
		const verdict = basicSplice.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on rate limit (429)", () => {
		const verdict = basicSplice.verify(makeResponse(429), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("fails when AS accepts (200)", () => {
		const verdict = basicSplice.verify(makeResponse(200, { access_token: "bad" }), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});
});

describe("actor-client-mismatch verify", () => {
	it("passes when AS rejects", () => {
		const verdict = actorClientMismatch.verify(makeResponse(400), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS accepts", () => {
		const verdict = actorClientMismatch.verify(makeResponse(200), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips on auth error", () => {
		const verdict = actorClientMismatch.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("aud-sub-binding verify", () => {
	it("passes when AS rejects", () => {
		const verdict = audSubBinding.verify(makeResponse(400), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS accepts", () => {
		const verdict = audSubBinding.verify(makeResponse(200), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips on auth error (401)", () => {
		const verdict = audSubBinding.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("upstream-splice verify", () => {
	it("passes when AS rejects re-delegation", () => {
		const verdict = upstreamSplice.verify(makeResponse(400), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS accepts re-delegation", () => {
		const verdict = upstreamSplice.verify(makeResponse(200), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips on server error (500)", () => {
		const verdict = upstreamSplice.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("subject-actor-swap verify", () => {
	it("passes when AS rejects", () => {
		const verdict = subjectActorSwap.verify(makeResponse(400), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS accepts", () => {
		const verdict = subjectActorSwap.verify(makeResponse(200), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});
});

describe("multi-audience verify", () => {
	it("passes when AS rejects with multi-aud token", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMultiAud: true } };
		const verdict = multiAudience.verify(makeResponse(400), setup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS accepts with multi-aud token", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMultiAud: true } };
		const verdict = multiAudience.verify(makeResponse(200), setup);
		expect(verdict).toHaveProperty("passed", false);
		expect("reason" in verdict && verdict.reason).toContain("multi-audience");
	});

	it("fails when AS accepts without multi-aud (basic splice detected)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMultiAud: false } };
		const verdict = multiAudience.verify(makeResponse(200), setup);
		expect(verdict).toHaveProperty("passed", false);
	});
});

describe("missing-aud verify", () => {
	it("passes when AS rejects regardless of aud presence", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasAud: false } };
		const verdict = missingAud.verify(makeResponse(400), setup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS accepts token without aud", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasAud: false } };
		const verdict = missingAud.verify(makeResponse(200), setup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("fails when AS accepts despite aud presence", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasAud: true } };
		const verdict = missingAud.verify(makeResponse(200), setup);
		expect(verdict).toHaveProperty("passed", false);
	});
});

describe("may-act-enforcement verify", () => {
	it("passes when AS enforces may_act", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMayAct: true } };
		const verdict = mayActEnforcement.verify(makeResponse(400), setup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS ignores may_act", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMayAct: true } };
		const verdict = mayActEnforcement.verify(makeResponse(200), setup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips when may_act not present and AS accepts", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMayAct: false } };
		const verdict = mayActEnforcement.verify(makeResponse(200), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("passes when may_act not present but AS still rejects", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMayAct: false } };
		const verdict = mayActEnforcement.verify(makeResponse(400), setup);
		expect(verdict).toHaveProperty("passed", true);
	});
});

describe("scope-escalation verify", () => {
	it("passes when AS rejects scope escalation", () => {
		const verdict = scopeEscalation.verify(
			makeResponse(400, { error: "invalid_scope" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("passes when AS constrains scope (no admin/write/delete)", () => {
		const verdict = scopeEscalation.verify(
			makeResponse(200, { access_token: "tok", scope: "openid profile" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS grants escalated scope", () => {
		const verdict = scopeEscalation.verify(
			makeResponse(200, { access_token: "tok", scope: "openid profile admin" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("fails when AS grants 200 with no scope in response", () => {
		const verdict = scopeEscalation.verify(makeResponse(200, { access_token: "tok" }), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});
});

describe("delegation-impersonation-confusion verify", () => {
	it("skips when exchange is rejected", () => {
		const verdict = delegationImpersonationConfusion.verify(makeResponse(400), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("fails when 200 but no access_token", () => {
		const verdict = delegationImpersonationConfusion.verify(makeResponse(200, {}), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips when token is opaque (not JWT)", () => {
		const verdict = delegationImpersonationConfusion.verify(
			makeResponse(200, { access_token: "opaque-not-jwt" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("refresh-bypass verify", () => {
	it("passes when AS rejects refresh after revocation", () => {
		const verdict = refreshBypass.verify(makeResponse(400, { error: "invalid_grant" }), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when refresh succeeds after revocation (bypass detected)", () => {
		const verdict = refreshBypass.verify(makeResponse(200, { access_token: "new" }), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("fails on unexpected response", () => {
		const verdict = refreshBypass.verify(makeResponse(302), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});
});

describe("revocation-propagation verify", () => {
	it("passes when downstream token is inactive after revocation", () => {
		const verdict = revocationPropagation.verify(makeResponse(200, { active: false }), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when downstream token remains active", () => {
		const verdict = revocationPropagation.verify(makeResponse(200, { active: true }), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips when introspection returns 401", () => {
		const verdict = revocationPropagation.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips when introspection returns other error", () => {
		const verdict = revocationPropagation.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

// ---------------------------------------------------------------------------
// Test metadata
// ---------------------------------------------------------------------------

describe("test metadata", () => {
	it("all tests have unique IDs", async () => {
		const { allTests: tests } = await import("../src/tests/index.js");
		const ids = tests.map((t) => t.id);
		expect(new Set(ids).size).toBe(ids.length);
	});

	it("all tests reference RFC specs", async () => {
		const { allTests: tests } = await import("../src/tests/index.js");
		for (const test of tests) {
			expect(test.spec).toMatch(/RFC/);
		}
	});

	it("all tests have severity ratings", async () => {
		const { allTests: tests } = await import("../src/tests/index.js");
		const validSeverities = ["critical", "high", "medium", "low"];
		for (const test of tests) {
			expect(validSeverities).toContain(test.severity);
		}
	});

	it("has expected number of tests (13)", async () => {
		const { allTests: tests } = await import("../src/tests/index.js");
		expect(tests).toHaveLength(13);
	});
});

// ---------------------------------------------------------------------------
// helpers.ts
// ---------------------------------------------------------------------------

describe("requireToken", () => {
	it("returns the token if present", () => {
		const setup: SetupResult = { tokens: { myToken: "abc123" } };
		expect(requireToken(setup, "myToken")).toBe("abc123");
	});

	it("throws if token is missing", () => {
		const setup: SetupResult = { tokens: {} };
		expect(() => requireToken(setup, "missing")).toThrow('expected token "missing"');
	});
});

describe("redactTokens", () => {
	it("replaces known token values with [REDACTED:name]", () => {
		const tokens = { aliceToken: "eyJhbGciOiJSUzI1NiJ9.payload.sig" };
		const msg = "Using token eyJhbGciOiJSUzI1NiJ9.payload.sig for exchange";
		expect(redactTokens(msg, tokens)).toBe("Using token [REDACTED:aliceToken] for exchange");
	});

	it("ignores short tokens (< 8 chars)", () => {
		const tokens = { short: "abc" };
		const msg = "Token: abc";
		expect(redactTokens(msg, tokens)).toBe("Token: abc");
	});

	it("handles empty tokens map", () => {
		expect(redactTokens("hello", {})).toBe("hello");
	});

	it("redacts multiple different tokens", () => {
		const tokens = {
			aliceToken: "alice-token-12345678",
			agentToken: "agent-token-87654321",
		};
		const msg = "Exchange alice-token-12345678 with actor agent-token-87654321";
		expect(redactTokens(msg, tokens)).toBe(
			"Exchange [REDACTED:aliceToken] with actor [REDACTED:agentToken]",
		);
	});
});
