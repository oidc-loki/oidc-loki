/**
 * Latency Injection - "The Loki Lag"
 *
 * Injects artificial delay into responses to test client timeout handling.
 * Clients should implement reasonable timeouts and not hang indefinitely.
 *
 * Spec: OIDC Core 1.0 Section 3.1.2.1 - Clients SHOULD implement timeouts
 */

import type { MischiefPlugin } from "../types.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export const latencyInjectionPlugin: MischiefPlugin = {
	id: "latency-injection",
	name: "The Loki Lag",
	severity: "medium",
	phase: "response",

	spec: {
		oidc: "OIDC Core 1.0 Section 3.1.2.1",
		description: "Clients SHOULD implement reasonable timeouts for IdP responses",
	},

	description: "Injects artificial delay to test client timeout handling",

	async apply(ctx) {
		if (!ctx.response) {
			return { applied: false, mutation: "No response context", evidence: {} };
		}

		const delayMs = (ctx.config.delayMs as number | undefined) ?? 5000;

		await sleep(delayMs);

		return {
			applied: true,
			mutation: `Delayed response by ${delayMs}ms`,
			evidence: {
				delayMs,
			},
		};
	},
};
