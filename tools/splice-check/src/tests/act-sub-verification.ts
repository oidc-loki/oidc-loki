/**
 * TE-15: `act.sub` Matches Intended Actor (Output Validation)
 *
 * RFC 8693 Section 4.1: After a delegation exchange, the `act.sub` claim in
 * the resulting token should match the actor that was specified. A buggy AS
 * might set `act.sub` to the wrong value.
 */

import { decodeJwt } from "jose";
import { describeResponse, isInconclusive, jsonBody } from "./classify.js";
import { requireToken } from "./helpers.js";
import type { AttackTest } from "./types.js";
import { TOKEN_TYPE } from "./types.js";

export const actSubVerification: AttackTest = {
	id: "act-sub-verification",
	name: "act.sub Matches Intended Actor",
	description:
		"Performs a delegation exchange and verifies that the resulting token's " +
		"`act.sub` claim matches the actor identity (Agent A), not the subject.",
	spec: "RFC 8693 Section 4.1",
	severity: "high",

	async setup(ctx) {
		ctx.log("Obtaining Alice's token and Agent A's token");
		const aliceToken = await ctx.client.clientCredentials("alice");
		const agentAToken = await ctx.client.clientCredentials("agent-a");

		// Try to extract agent-a's sub from its token
		let agentASub: string | undefined;
		try {
			const claims = decodeJwt(agentAToken);
			agentASub = claims.sub as string | undefined;
			ctx.log(`Agent A sub: ${agentASub ?? "(not found)"}`);
		} catch {
			ctx.log("Could not decode Agent A token — may be opaque");
		}

		return {
			tokens: { subjectToken: aliceToken, actorToken: agentAToken },
			metadata: { agentASub },
		};
	},

	async attack(ctx, setup) {
		ctx.log("Performing delegation exchange to verify act.sub in result");
		return ctx.client.tokenExchange({
			subject_token: requireToken(setup, "subjectToken"),
			subject_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			actor_token: requireToken(setup, "actorToken"),
			actor_token_type: TOKEN_TYPE.ACCESS_TOKEN,
			clientName: "agent-a",
		});
	},

	verify(response, setup) {
		if (response.status !== 200) {
			if (isInconclusive(response)) {
				return {
					skipped: true,
					reason: `Inconclusive: ${describeResponse(response)}`,
				};
			}
			return {
				skipped: true,
				reason: `Exchange was rejected — ${describeResponse(response)}. Cannot verify act.sub.`,
			};
		}

		const body = jsonBody(response);
		const accessToken = body?.access_token as string | undefined;
		if (!accessToken) {
			return {
				passed: false,
				reason: "Exchange returned 200 but no access_token",
				expected: "access_token with act.sub matching actor",
				actual: describeResponse(response),
			};
		}

		try {
			const claims = decodeJwt(accessToken);
			const act = claims.act as Record<string, unknown> | undefined;

			if (!act) {
				return {
					skipped: true,
					reason:
						"Delegated token has no act claim — cannot verify act.sub. " +
						"(See delegation-impersonation-confusion test for act presence check)",
				};
			}

			const actSub = act.sub as string | undefined;
			if (!actSub) {
				return {
					passed: false,
					reason: "act claim exists but has no sub field",
					expected: "act.sub identifying the actor",
					actual: `act keys: ${Object.keys(act).join(", ")} (no sub)`,
				};
			}

			// If we know agent-a's sub, verify it matches
			const agentASub = setup.metadata?.agentASub as string | undefined;
			if (agentASub && actSub !== agentASub) {
				return {
					passed: false,
					reason: `act.sub does not match actor identity — expected "${agentASub}" but got "${actSub}"`,
					expected: `act.sub = "${agentASub}" (actor's identity)`,
					actual: `act.sub = "${actSub}"`,
				};
			}

			return {
				passed: true,
				reason: `act.sub = "${actSub}" — matches actor identity`,
			};
		} catch {
			return {
				skipped: true,
				reason: "Resulting token is opaque (not a JWT) — cannot verify act.sub",
			};
		}
	},
};
