/**
 * TE-13: Token Lifetime Reduction Verification
 *
 * RFC 8693 Section 2.2 and RFC 9700 recommend that delegated tokens have
 * equal or shorter lifetimes than the original subject_token. If delegation
 * extends the token's lifetime, it undermines time-based access control.
 */

import { decodeJwt } from "jose";
import { describeResponse, isInconclusive, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const tokenLifetimeReduction: AttackTest = {
	id: "token-lifetime-reduction",
	name: "Token Lifetime Reduction",
	description:
		"Verifies that delegated tokens have equal or shorter lifetimes than the original. " +
		"If exchange extends token lifetime, it becomes a persistence mechanism.",
	spec: "RFC 8693 Section 2.2 / RFC 9700",
	severity: "medium",

	async setup(ctx) {
		ctx.log("Obtaining Alice's access_token and recording its expiry");
		const aliceToken = await ctx.client.clientCredentials("alice");

		let originalExp: number | undefined;
		try {
			const claims = decodeJwt(aliceToken);
			originalExp = claims.exp;
			if (originalExp) {
				ctx.log(`Original token exp: ${new Date(originalExp * 1000).toISOString()}`);
			} else {
				ctx.log("Original token has no exp claim");
			}
		} catch {
			ctx.log("Could not decode original token — may be opaque");
		}

		return {
			tokens: { subjectToken: aliceToken },
			metadata: { originalExp },
		};
	},

	async attack(ctx, setup) {
		ctx.log("Performing delegation exchange to compare token lifetimes");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
		});
	},

	verify(response, setup) {
		const originalExp = setup.metadata?.originalExp as number | undefined;

		if (response.status !== 200) {
			if (isInconclusive(response)) {
				return {
					skipped: true,
					reason: `Inconclusive: ${describeResponse(response)}`,
				};
			}
			return {
				skipped: true,
				reason: `Exchange was rejected — ${describeResponse(response)}. Cannot compare lifetimes.`,
			};
		}

		const body = jsonBody(response);
		const accessToken = body?.access_token as string | undefined;
		if (!accessToken) {
			return {
				passed: false,
				reason: "Exchange returned 200 but no access_token",
				expected: "access_token to compare lifetime",
				actual: describeResponse(response),
			};
		}

		if (originalExp === undefined) {
			return {
				skipped: true,
				reason: "Original token has no exp claim — cannot compare lifetimes",
			};
		}

		try {
			const claims = decodeJwt(accessToken);
			if (claims.exp === undefined) {
				return {
					passed: false,
					reason:
						"Delegated token has no exp claim — token never expires, " +
						"original had finite lifetime",
					expected: "exp ≤ original token's exp",
					actual: "No exp claim in delegated token",
				};
			}

			if (claims.exp > originalExp) {
				return {
					passed: false,
					reason:
						"Delegated token expires AFTER the original — " +
						"exchange extended token lifetime (persistence vector)",
					expected: `exp ≤ ${originalExp} (${new Date(originalExp * 1000).toISOString()})`,
					actual: `exp = ${claims.exp} (${new Date(claims.exp * 1000).toISOString()})`,
				};
			}

			return {
				passed: true,
				reason: `Delegated token lifetime constrained (exp ${claims.exp} ≤ original ${originalExp})`,
			};
		} catch {
			return {
				skipped: true,
				reason: "Resulting token is opaque (not a JWT) — cannot verify lifetime",
			};
		}
	},
};
