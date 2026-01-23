/**
 * Scope Injection Attack
 *
 * Manipulates the scope claim to test if clients properly validate
 * that tokens have only the scopes that were requested and authorized.
 *
 * Real-world impact: Privilege escalation, unauthorized access to resources
 *
 * Modes:
 * - inject: Adds additional privileged scopes to the token
 * - replace: Replaces scope with attacker-controlled value
 * - admin: Adds common admin/elevated scopes
 * - remove: Removes the scope claim entirely
 *
 * Spec: RFC 6749 Section 3.3 - Access Token Scope
 * Spec: RFC 8693 - Token Exchange (scope handling)
 * CWE-269: Improper Privilege Management
 */

import type { MischiefPlugin } from "../types.js";

type ScopeMode = "inject" | "replace" | "admin" | "remove";

export const scopeInjectionPlugin: MischiefPlugin = {
	id: "scope-injection",
	name: "Scope Injection",
	severity: "critical",
	phase: "token-claims",

	spec: {
		rfc: "RFC 6749 Section 3.3",
		cwe: "CWE-269",
		description: "The 'scope' claim MUST be validated to ensure only authorized scopes are present",
	},

	description: "Manipulates scope claim to test privilege validation",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const mode = (ctx.config.mode as ScopeMode | undefined) ?? "inject";
		const originalScope = ctx.token.claims.scope as string | undefined;

		let newScope: string | undefined;
		let mutation: string;

		switch (mode) {
			case "inject": {
				// Add malicious scopes to existing ones
				const injectedScopes =
					(ctx.config.injectScopes as string | undefined) ?? "admin write:all delete:all";
				if (originalScope) {
					newScope = `${originalScope} ${injectedScopes}`;
				} else {
					newScope = injectedScopes;
				}
				mutation = `Injected additional scopes: ${injectedScopes}`;
				break;
			}

			case "replace": {
				// Completely replace scope
				newScope =
					(ctx.config.replaceScope as string | undefined) ??
					"openid profile email admin:* system:*";
				mutation = `Replaced scope with: ${newScope}`;
				break;
			}

			case "admin": {
				// Add common admin/privileged scope patterns
				const adminScopes = [
					"admin",
					"admin:*",
					"write:*",
					"delete:*",
					"system:admin",
					"superuser",
					"root",
					"manage:users",
					"manage:all",
				].join(" ");

				if (originalScope) {
					newScope = `${originalScope} ${adminScopes}`;
				} else {
					newScope = adminScopes;
				}
				mutation = "Injected common admin/privileged scopes";
				break;
			}

			case "remove":
				newScope = undefined;
				mutation = "Removed scope claim entirely";
				break;

			default:
				return {
					applied: false,
					mutation: `Unknown mode: ${mode}`,
					evidence: { mode },
				};
		}

		if (newScope === undefined) {
			ctx.token.claims.scope = undefined;
		} else {
			ctx.token.claims.scope = newScope;
		}

		return {
			applied: true,
			mutation,
			evidence: {
				mode,
				originalScope: originalScope ?? null,
				newScope: newScope ?? null,
				attackType: "scope-injection",
			},
		};
	},
};
