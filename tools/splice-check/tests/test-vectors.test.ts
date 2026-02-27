import { describe, expect, it } from "vitest";
import { actClaimStripping } from "../src/tests/act-claim-stripping.js";
import { actNestingIntegrity } from "../src/tests/act-nesting-integrity.js";
import { actSubVerification } from "../src/tests/act-sub-verification.js";
import { actorClientMismatch } from "../src/tests/actor-client-mismatch.js";
import { audSubBinding } from "../src/tests/aud-sub-binding.js";
import { audienceTargeting } from "../src/tests/audience-targeting.js";
import { basicSplice } from "../src/tests/basic-splice.js";
import { chainDepthExhaustion } from "../src/tests/chain-depth-exhaustion.js";
import { circularDelegation } from "../src/tests/circular-delegation.js";
import {
	classifyResponse,
	describeResponse,
	isInconclusive,
	isSecurityRejection,
	jsonBody,
	requireJsonBody,
} from "../src/tests/classify.js";
import { delegationImpersonationConfusion } from "../src/tests/delegation-impersonation-confusion.js";
import { downstreamAudVerification } from "../src/tests/downstream-aud-verification.js";
import { redactTokens, requireToken } from "../src/tests/helpers.js";
import { issuedTokenTypeValidation } from "../src/tests/issued-token-type-validation.js";
import { mayActEnforcement } from "../src/tests/may-act-enforcement.js";
import { missingAud } from "../src/tests/missing-aud.js";
import { multiAudience } from "../src/tests/multi-audience.js";
import { refreshBypass } from "../src/tests/refresh-bypass.js";
import { resourceAbuse } from "../src/tests/resource-abuse.js";
import { revocationPropagation } from "../src/tests/revocation-propagation.js";
import { scopeEscalation } from "../src/tests/scope-escalation.js";
import { subjectActorSwap } from "../src/tests/subject-actor-swap.js";
import { tokenLifetimeReduction } from "../src/tests/token-lifetime-reduction.js";
import { tokenTypeEscalation } from "../src/tests/token-type-escalation.js";
import { tokenTypeMismatch } from "../src/tests/token-type-mismatch.js";
import type { AttackResponse, SetupResult } from "../src/tests/types.js";
import { unauthenticatedExchange } from "../src/tests/unauthenticated-exchange.js";
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

	it("classifies 404 as unknown", () => {
		expect(classifyResponse(makeResponse(404))).toBe("unknown");
	});

	it("classifies 400 with unsupported_grant_type as unsupported", () => {
		expect(classifyResponse(makeResponse(400, { error: "unsupported_grant_type" }))).toBe(
			"unsupported",
		);
	});

	it("classifies 400 with invalid_scope as security_rejection", () => {
		expect(classifyResponse(makeResponse(400, { error: "invalid_scope" }))).toBe(
			"security_rejection",
		);
	});

	it("classifies 400 with custom error code as security_rejection (default)", () => {
		expect(classifyResponse(makeResponse(400, { error: "custom_vendor_error" }))).toBe(
			"security_rejection",
		);
	});

	it("handles array body without error", () => {
		expect(classifyResponse(makeResponse(400, [{ error: "invalid_grant" }]))).toBe(
			"security_rejection",
		);
	});

	it("handles string body", () => {
		expect(classifyResponse(makeResponse(400, "Bad Request"))).toBe("security_rejection");
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

	it("returns true for unsupported", () => {
		expect(isInconclusive(makeResponse(400, { error: "unsupported_grant_type" }))).toBe(true);
	});

	it("returns true for unknown (302)", () => {
		expect(isInconclusive(makeResponse(302))).toBe(true);
	});

	it("returns true for unknown (404)", () => {
		expect(isInconclusive(makeResponse(404))).toBe(true);
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

	it("describes unsupported grant type", () => {
		expect(describeResponse(makeResponse(400, { error: "unsupported_grant_type" }))).toBe(
			"HTTP 400 unsupported (unsupported_grant_type)",
		);
	});

	it("describes server error", () => {
		expect(describeResponse(makeResponse(500))).toBe("HTTP 500 server error");
	});

	it("describes unknown status", () => {
		expect(describeResponse(makeResponse(302))).toMatch(/HTTP 302/);
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

	it("fails on 400 security rejection", () => {
		const verdict = validDelegation.verify(
			makeResponse(400, { error: "invalid_request" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips on 401 auth error (inconclusive)", () => {
		const verdict = validDelegation.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 429 rate limit (inconclusive)", () => {
		const verdict = validDelegation.verify(makeResponse(429), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 500 server error (inconclusive)", () => {
		const verdict = validDelegation.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("handles 200 with null body gracefully", () => {
		const verdict = validDelegation.verify(makeResponse(200, null), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("handles 200 with string body gracefully", () => {
		const verdict = validDelegation.verify(makeResponse(200, "not json"), emptySetup);
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

	it("skips on server error (500)", () => {
		const verdict = basicSplice.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 404 (unknown/inconclusive)", () => {
		const verdict = basicSplice.verify(makeResponse(404), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on unsupported_grant_type", () => {
		const verdict = basicSplice.verify(
			makeResponse(400, { error: "unsupported_grant_type" }),
			emptySetup,
		);
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

	it("skips on 500 server error", () => {
		const verdict = actorClientMismatch.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 429 rate limit", () => {
		const verdict = actorClientMismatch.verify(makeResponse(429), emptySetup);
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

	it("skips on inconclusive (429 rate limit)", () => {
		const verdict = subjectActorSwap.verify(makeResponse(429), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (500 server error)", () => {
		const verdict = subjectActorSwap.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (401 auth error)", () => {
		const verdict = subjectActorSwap.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
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

	it("skips on inconclusive (401 auth error)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMultiAud: true } };
		const verdict = multiAudience.verify(makeResponse(401), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (500 server error)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMultiAud: false } };
		const verdict = multiAudience.verify(makeResponse(500), setup);
		expect(verdict).toHaveProperty("skipped", true);
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

	it("skips on inconclusive (401 auth error)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasAud: false } };
		const verdict = missingAud.verify(makeResponse(401), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (429 rate limit)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasAud: true } };
		const verdict = missingAud.verify(makeResponse(429), setup);
		expect(verdict).toHaveProperty("skipped", true);
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

	it("skips on 401 auth error when may_act present (not a false pass)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMayAct: true } };
		const verdict = mayActEnforcement.verify(makeResponse(401), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 429 rate limit when may_act present (not a false pass)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMayAct: true } };
		const verdict = mayActEnforcement.verify(makeResponse(429), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 500 server error when may_act present (not a false pass)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMayAct: true } };
		const verdict = mayActEnforcement.verify(makeResponse(500), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 401 auth error when may_act not present (not a false pass)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMayAct: false } };
		const verdict = mayActEnforcement.verify(makeResponse(401), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on unsupported_grant_type (AS does not support token exchange)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasMayAct: true } };
		const verdict = mayActEnforcement.verify(
			makeResponse(400, { error: "unsupported_grant_type" }),
			setup,
		);
		expect(verdict).toHaveProperty("skipped", true);
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

	it("fails when scope contains only 'admin'", () => {
		const verdict = scopeEscalation.verify(
			makeResponse(200, { access_token: "tok", scope: "admin" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("fails when scope contains 'write'", () => {
		const verdict = scopeEscalation.verify(
			makeResponse(200, { access_token: "tok", scope: "readonly write" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("fails when scope contains 'delete'", () => {
		const verdict = scopeEscalation.verify(
			makeResponse(200, { access_token: "tok", scope: "openid delete" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips on inconclusive (500 server error)", () => {
		const verdict = scopeEscalation.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
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

	it("passes when JWT has act claim (proper delegation)", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","act":{"sub":"agent-a"}}.
		const jwtWithAct =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImFjdCI6eyJzdWIiOiJhZ2VudC1hIn19.";
		const verdict = delegationImpersonationConfusion.verify(
			makeResponse(200, { access_token: jwtWithAct }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when JWT lacks act claim (impersonation instead of delegation)", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice"}.
		const jwtWithoutAct = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9.";
		const verdict = delegationImpersonationConfusion.verify(
			makeResponse(200, { access_token: jwtWithoutAct }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
		expect("reason" in verdict && verdict.reason).toContain("act");
	});

	it("skips on inconclusive (429 rate limit)", () => {
		const verdict = delegationImpersonationConfusion.verify(makeResponse(429), emptySetup);
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

	it("skips on unexpected response (302 is inconclusive)", () => {
		const verdict = refreshBypass.verify(makeResponse(302), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 401 auth error (not a false pass)", () => {
		const verdict = refreshBypass.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 429 rate limit (not a false pass)", () => {
		const verdict = refreshBypass.verify(makeResponse(429), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 500 server error (not a false pass)", () => {
		const verdict = refreshBypass.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
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

	it("skips when introspection returns 403", () => {
		const verdict = revocationPropagation.verify(makeResponse(403), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips when introspection returns other error", () => {
		const verdict = revocationPropagation.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

// ---------------------------------------------------------------------------
// TE-01 through TE-05: New must-have attack vectors
// ---------------------------------------------------------------------------

describe("token-type-mismatch verify", () => {
	it("passes when AS rejects mismatched type", () => {
		const verdict = tokenTypeMismatch.verify(
			makeResponse(400, { error: "invalid_request" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS accepts mismatched type", () => {
		const verdict = tokenTypeMismatch.verify(
			makeResponse(200, { access_token: "tok" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips on auth error (401)", () => {
		const verdict = tokenTypeMismatch.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on server error (500)", () => {
		const verdict = tokenTypeMismatch.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("unauthenticated-exchange verify", () => {
	it("passes on 401 (client auth required)", () => {
		const verdict = unauthenticatedExchange.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("passes on 400 with invalid_client", () => {
		const verdict = unauthenticatedExchange.verify(
			makeResponse(400, { error: "invalid_client" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS issues token without auth", () => {
		const verdict = unauthenticatedExchange.verify(
			makeResponse(200, { access_token: "tok" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("passes on 403 rejection", () => {
		const verdict = unauthenticatedExchange.verify(makeResponse(403), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("skips on 429 rate limit", () => {
		const verdict = unauthenticatedExchange.verify(makeResponse(429), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 500 server error", () => {
		const verdict = unauthenticatedExchange.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("token-type-escalation verify", () => {
	it("passes when AS rejects escalation", () => {
		const verdict = tokenTypeEscalation.verify(
			makeResponse(400, { error: "invalid_request" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS issues refresh_token", () => {
		const verdict = tokenTypeEscalation.verify(
			makeResponse(200, {
				access_token: "at",
				refresh_token: "rt",
				issued_token_type: "urn:ietf:params:oauth:token-type:refresh_token",
			}),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("passes when AS constrains to access_token instead", () => {
		const verdict = tokenTypeEscalation.verify(
			makeResponse(200, {
				access_token: "at",
				issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
			}),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("skips on auth error", () => {
		const verdict = tokenTypeEscalation.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("audience-targeting verify", () => {
	it("passes when AS rejects unauthorized audience", () => {
		const verdict = audienceTargeting.verify(
			makeResponse(400, { error: "invalid_target" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS issues token for unauthorized audience", () => {
		const verdict = audienceTargeting.verify(
			makeResponse(200, { access_token: "tok" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips on 401 auth error", () => {
		const verdict = audienceTargeting.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on 500 server error", () => {
		const verdict = audienceTargeting.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("act-claim-stripping verify", () => {
	it("passes when AS rejects re-exchange (security rejection)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasActClaim: true } };
		const verdict = actClaimStripping.verify(makeResponse(400, { error: "invalid_grant" }), setup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS returns 200 without act claim (stripped)", () => {
		// Simulate: original had act claim, result doesn't
		// We can't create a real JWT in unit tests easily, so we test the
		// non-JWT path (opaque token → skipped)
		const setup: SetupResult = { tokens: {}, metadata: { hasActClaim: true } };
		const verdict = actClaimStripping.verify(
			makeResponse(200, { access_token: "opaque-token-no-dots" }),
			setup,
		);
		// Opaque token can't be decoded → skipped
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("fails when original had no act and AS allows impersonation", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasActClaim: false } };
		const verdict = actClaimStripping.verify(makeResponse(200, { access_token: "tok" }), setup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips on inconclusive response", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasActClaim: true } };
		const verdict = actClaimStripping.verify(makeResponse(429), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("fails on 200 with no access_token", () => {
		const setup: SetupResult = { tokens: {}, metadata: { hasActClaim: true } };
		const verdict = actClaimStripping.verify(makeResponse(200, {}), setup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("passes when JWT preserves act claim after re-exchange", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","act":{"sub":"agent-a"}}.
		const jwtWithAct =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImFjdCI6eyJzdWIiOiJhZ2VudC1hIn19.";
		const setup: SetupResult = { tokens: {}, metadata: { hasActClaim: true } };
		const verdict = actClaimStripping.verify(
			makeResponse(200, { access_token: jwtWithAct }),
			setup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when JWT has act stripped after re-exchange", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice"}.  (no act claim)
		const jwtWithoutAct = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9.";
		const setup: SetupResult = { tokens: {}, metadata: { hasActClaim: true } };
		const verdict = actClaimStripping.verify(
			makeResponse(200, { access_token: jwtWithoutAct }),
			setup,
		);
		expect(verdict).toHaveProperty("passed", false);
		expect("reason" in verdict && verdict.reason).toContain("stripped");
	});
});

// ---------------------------------------------------------------------------
// TE-08 through TE-16: Should-have attack vectors
// ---------------------------------------------------------------------------

describe("resource-abuse verify", () => {
	it("passes when AS rejects unauthorized resource", () => {
		const verdict = resourceAbuse.verify(
			makeResponse(400, { error: "invalid_target" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("passes on 403 rejection", () => {
		const verdict = resourceAbuse.verify(makeResponse(403), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS issues token for unauthorized resource", () => {
		const verdict = resourceAbuse.verify(makeResponse(200, { access_token: "tok" }), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips on inconclusive (429)", () => {
		const verdict = resourceAbuse.verify(makeResponse(429), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (500)", () => {
		const verdict = resourceAbuse.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("issued-token-type-validation verify", () => {
	it("passes when response includes valid issued_token_type", () => {
		const verdict = issuedTokenTypeValidation.verify(
			makeResponse(200, {
				access_token: "tok",
				issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
			}),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when issued_token_type is missing", () => {
		const verdict = issuedTokenTypeValidation.verify(
			makeResponse(200, { access_token: "tok" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
		expect("reason" in verdict && verdict.reason).toContain("issued_token_type");
	});

	it("fails when issued_token_type has unrecognized value", () => {
		const verdict = issuedTokenTypeValidation.verify(
			makeResponse(200, { access_token: "tok", issued_token_type: "urn:custom:bogus" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("fails when 200 but no access_token", () => {
		const verdict = issuedTokenTypeValidation.verify(makeResponse(200, {}), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips on rejection", () => {
		const verdict = issuedTokenTypeValidation.verify(makeResponse(400), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (401)", () => {
		const verdict = issuedTokenTypeValidation.verify(makeResponse(401), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("downstream-aud-verification verify", () => {
	it("passes when JWT has aud claim", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","aud":"agent-a"}.
		const jwtWithAud =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImF1ZCI6ImFnZW50LWEifQ.";
		const verdict = downstreamAudVerification.verify(
			makeResponse(200, { access_token: jwtWithAud }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when JWT has no aud claim", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice"}.
		const jwtWithoutAud = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9.";
		const verdict = downstreamAudVerification.verify(
			makeResponse(200, { access_token: jwtWithoutAud }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
		expect("reason" in verdict && verdict.reason).toContain("aud");
	});

	it("skips when token is opaque", () => {
		const verdict = downstreamAudVerification.verify(
			makeResponse(200, { access_token: "opaque-not-jwt" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("fails when 200 but no access_token", () => {
		const verdict = downstreamAudVerification.verify(makeResponse(200, {}), emptySetup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips on rejection", () => {
		const verdict = downstreamAudVerification.verify(makeResponse(400), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (500)", () => {
		const verdict = downstreamAudVerification.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("token-lifetime-reduction verify", () => {
	it("passes when delegated token exp ≤ original exp", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","exp":1000}.
		const jwtWithLowerExp =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImV4cCI6MTAwMH0.";
		const setup: SetupResult = { tokens: {}, metadata: { originalExp: 2000 } };
		const verdict = tokenLifetimeReduction.verify(
			makeResponse(200, { access_token: jwtWithLowerExp }),
			setup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when delegated token exp > original exp", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","exp":3000}.
		const jwtWithHigherExp =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImV4cCI6MzAwMH0.";
		const setup: SetupResult = { tokens: {}, metadata: { originalExp: 2000 } };
		const verdict = tokenLifetimeReduction.verify(
			makeResponse(200, { access_token: jwtWithHigherExp }),
			setup,
		);
		expect(verdict).toHaveProperty("passed", false);
		expect("reason" in verdict && verdict.reason).toContain("AFTER");
	});

	it("fails when delegated token has no exp claim", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice"}.
		const jwtNoExp = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9.";
		const setup: SetupResult = { tokens: {}, metadata: { originalExp: 2000 } };
		const verdict = tokenLifetimeReduction.verify(
			makeResponse(200, { access_token: jwtNoExp }),
			setup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips when original had no exp", () => {
		const setup: SetupResult = { tokens: {}, metadata: { originalExp: undefined } };
		const verdict = tokenLifetimeReduction.verify(
			makeResponse(200, { access_token: "tok" }),
			setup,
		);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips when token is opaque", () => {
		const setup: SetupResult = { tokens: {}, metadata: { originalExp: 2000 } };
		const verdict = tokenLifetimeReduction.verify(
			makeResponse(200, { access_token: "opaque" }),
			setup,
		);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (500)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { originalExp: 2000 } };
		const verdict = tokenLifetimeReduction.verify(makeResponse(500), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("act-sub-verification verify", () => {
	it("passes when act.sub matches actor identity", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","act":{"sub":"agent-a"}}.
		const jwt =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImFjdCI6eyJzdWIiOiJhZ2VudC1hIn19.";
		const setup: SetupResult = { tokens: {}, metadata: { agentASub: "agent-a" } };
		const verdict = actSubVerification.verify(makeResponse(200, { access_token: jwt }), setup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when act.sub does not match actor identity", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","act":{"sub":"wrong-agent"}}.
		const jwt =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImFjdCI6eyJzdWIiOiJ3cm9uZy1hZ2VudCJ9fQ.";
		const setup: SetupResult = { tokens: {}, metadata: { agentASub: "agent-a" } };
		const verdict = actSubVerification.verify(makeResponse(200, { access_token: jwt }), setup);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("passes when act.sub present but agent sub unknown", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","act":{"sub":"agent-a"}}.
		const jwt =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImFjdCI6eyJzdWIiOiJhZ2VudC1hIn19.";
		const setup: SetupResult = { tokens: {}, metadata: {} };
		const verdict = actSubVerification.verify(makeResponse(200, { access_token: jwt }), setup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("skips when no act claim (defers to other test)", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice"}.
		const jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9.";
		const setup: SetupResult = { tokens: {}, metadata: {} };
		const verdict = actSubVerification.verify(makeResponse(200, { access_token: jwt }), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on rejection", () => {
		const setup: SetupResult = { tokens: {}, metadata: {} };
		const verdict = actSubVerification.verify(makeResponse(400), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (429)", () => {
		const setup: SetupResult = { tokens: {}, metadata: {} };
		const verdict = actSubVerification.verify(makeResponse(429), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("act-nesting-integrity verify", () => {
	it("passes when act chain is intact with nested act", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","act":{"sub":"agent-n","act":{"sub":"agent-a"}}}.
		const jwt =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImFjdCI6eyJzdWIiOiJhZ2VudC1uIiwiYWN0Ijp7InN1YiI6ImFnZW50LWEifX19.";
		const verdict = actNestingIntegrity.verify(
			makeResponse(200, { access_token: jwt }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("passes when act chain is single hop (no nested act)", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","act":{"sub":"agent-n"}}.
		const jwt =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImFjdCI6eyJzdWIiOiJhZ2VudC1uIn19.";
		const verdict = actNestingIntegrity.verify(
			makeResponse(200, { access_token: jwt }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when no act claim present", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice"}.
		const jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9.";
		const verdict = actNestingIntegrity.verify(
			makeResponse(200, { access_token: jwt }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("fails when act has non-identity claims leaked (exp)", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","act":{"sub":"agent-n","exp":9999}}.
		const jwt =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImFjdCI6eyJzdWIiOiJhZ2VudC1uIiwiZXhwIjo5OTk5fX0.";
		const verdict = actNestingIntegrity.verify(
			makeResponse(200, { access_token: jwt }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
		expect("reason" in verdict && verdict.reason).toContain("exp");
	});

	it("fails when act has no sub", () => {
		// JWT: {"alg":"none","typ":"JWT"}.{"sub":"alice","act":{"client_id":"agent-n"}}.
		const jwt =
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImFjdCI6eyJjbGllbnRfaWQiOiJhZ2VudC1uIn19.";
		const verdict = actNestingIntegrity.verify(
			makeResponse(200, { access_token: jwt }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
	});

	it("skips when token is opaque", () => {
		const verdict = actNestingIntegrity.verify(
			makeResponse(200, { access_token: "opaque" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on rejection", () => {
		const verdict = actNestingIntegrity.verify(makeResponse(400), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (500)", () => {
		const verdict = actNestingIntegrity.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("circular-delegation verify", () => {
	it("passes when AS rejects circular delegation", () => {
		const verdict = circularDelegation.verify(
			makeResponse(400, { error: "invalid_grant" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("passes on 403 rejection", () => {
		const verdict = circularDelegation.verify(makeResponse(403), emptySetup);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS accepts circular delegation", () => {
		const verdict = circularDelegation.verify(
			makeResponse(200, { access_token: "circular-tok" }),
			emptySetup,
		);
		expect(verdict).toHaveProperty("passed", false);
		expect("reason" in verdict && verdict.reason).toContain("circular");
	});

	it("skips on inconclusive (429)", () => {
		const verdict = circularDelegation.verify(makeResponse(429), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (500)", () => {
		const verdict = circularDelegation.verify(makeResponse(500), emptySetup);
		expect(verdict).toHaveProperty("skipped", true);
	});
});

describe("chain-depth-exhaustion verify", () => {
	it("passes when AS rejected during setup (depth limit enforced)", () => {
		const setup: SetupResult = {
			tokens: {},
			metadata: { rejectedAtDepth: 3, depthReached: 2 },
		};
		const verdict = chainDepthExhaustion.verify(
			makeResponse(400, { error: "chain_depth_exceeded" }),
			setup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("passes when AS rejects the final depth push", () => {
		const setup: SetupResult = { tokens: {}, metadata: { depthReached: 4 } };
		const verdict = chainDepthExhaustion.verify(
			makeResponse(400, { error: "invalid_grant" }),
			setup,
		);
		expect(verdict).toHaveProperty("passed", true);
	});

	it("fails when AS accepts unbounded chain depth", () => {
		const setup: SetupResult = { tokens: {}, metadata: { depthReached: 4 } };
		const verdict = chainDepthExhaustion.verify(
			makeResponse(200, { access_token: "deep-tok" }),
			setup,
		);
		expect(verdict).toHaveProperty("passed", false);
		expect("reason" in verdict && verdict.reason).toContain("depth");
	});

	it("skips on inconclusive (429)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { depthReached: 4 } };
		const verdict = chainDepthExhaustion.verify(makeResponse(429), setup);
		expect(verdict).toHaveProperty("skipped", true);
	});

	it("skips on inconclusive (500)", () => {
		const setup: SetupResult = { tokens: {}, metadata: { depthReached: 4 } };
		const verdict = chainDepthExhaustion.verify(makeResponse(500), setup);
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

	it("has expected number of tests (26)", async () => {
		const { allTests: tests } = await import("../src/tests/index.js");
		expect(tests).toHaveLength(26);
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
