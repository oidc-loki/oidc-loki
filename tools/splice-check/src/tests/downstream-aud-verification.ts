/**
 * TE-12: Downstream Token `aud` Verification
 *
 * RFC 8693 Section 2.1 and the 8-Point Mitigation Profile require the AS to
 * set the new token's `aud` to the intended downstream consumer. Without this,
 * delegation tokens are bearer tokens usable anywhere.
 *
 * This test performs a delegation exchange and inspects the resulting token's
 * `aud` claim to verify it is set and constrained.
 */

import { decodeJwt } from "jose";
import { describeResponse, isInconclusive, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const downstreamAudVerification: AttackTest = {
	id: "downstream-aud-verification",
	name: "Downstream Token aud Verification",
	description:
		"Performs a delegation exchange and verifies the resulting token has a constrained " +
		"`aud` claim. Tokens without audience restriction can be replayed anywhere.",
	spec: "RFC 8693 Section 2.1 / 8-Point Mitigation Profile #4",
	severity: "high",

	async setup(ctx) {
		ctx.log("Obtaining Alice's access_token");
		const aliceToken = await ctx.client.clientCredentials("alice");

		return {
			tokens: { subjectToken: aliceToken },
		};
	},

	async attack(ctx, setup) {
		ctx.log("Performing delegation exchange to inspect output token aud claim");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
		});
	},

	verify(response) {
		if (response.status !== 200) {
			if (isInconclusive(response)) {
				return {
					skipped: true,
					reason: `Inconclusive: ${describeResponse(response)}`,
				};
			}
			return {
				skipped: true,
				reason: `Exchange was rejected — ${describeResponse(response)}. Cannot verify aud.`,
			};
		}

		const body = jsonBody(response);
		const accessToken = body?.access_token as string | undefined;
		if (!accessToken) {
			return {
				passed: false,
				reason: "Exchange returned 200 but no access_token",
				expected: "access_token with constrained aud claim",
				actual: describeResponse(response),
			};
		}

		try {
			const claims = decodeJwt(accessToken);
			if (claims.aud === undefined) {
				return {
					passed: false,
					reason:
						"Delegated token has no `aud` claim — token can be replayed to any resource server",
					expected: "JWT with constrained aud claim",
					actual: `JWT claims: ${Object.keys(claims).join(", ")} (no aud)`,
				};
			}
			return {
				passed: true,
				reason: `Delegated token has aud claim: ${JSON.stringify(claims.aud)}`,
			};
		} catch {
			return {
				skipped: true,
				reason: "Resulting token is opaque (not a JWT) — cannot verify aud claim",
			};
		}
	},
};
