/**
 * Subject Manipulation Attack
 *
 * Manipulates the subject (sub) claim to test if clients properly validate
 * user identity claims and prevent impersonation.
 *
 * Real-world impact: Account takeover, privilege escalation, impersonation
 *
 * Modes:
 * - impersonate: Changes sub to a different user ID
 * - admin: Changes sub to common admin identifiers
 * - empty: Sets sub to empty string
 * - numeric: Changes sub to numeric ID (type confusion)
 *
 * Spec: RFC 7519 Section 4.1.2 - sub claim identifies the principal
 * OIDC: OpenID Connect Core 1.0 Section 2 - sub is locally unique identifier
 * CWE-287: Improper Authentication
 */

import type { MischiefPlugin } from "../types.js";

type SubjectMode = "impersonate" | "admin" | "empty" | "numeric";

export const subjectManipulationPlugin: MischiefPlugin = {
	id: "subject-manipulation",
	name: "Subject Manipulation",
	severity: "critical",
	phase: "token-claims",

	spec: {
		rfc: "RFC 7519 Section 4.1.2",
		oidc: "OIDC Core 1.0 Section 2",
		cwe: "CWE-287",
		description: "The 'sub' claim MUST be validated and not trusted from untrusted sources",
	},

	description: "Manipulates subject claim to test identity validation",

	async apply(ctx) {
		if (!ctx.token) {
			return { applied: false, mutation: "No token context", evidence: {} };
		}

		const mode = (ctx.config.mode as SubjectMode | undefined) ?? "admin";
		const originalSub = ctx.token.claims.sub;

		let newSub: string | number;
		let mutation: string;

		switch (mode) {
			case "impersonate": {
				const targetUser = (ctx.config.targetUser as string | undefined) ?? "victim-user-id";
				newSub = targetUser;
				mutation = "Changed sub to impersonate another user";
				break;
			}

			case "admin": {
				// Try common admin identifiers
				const adminId = (ctx.config.adminId as string | undefined) ?? "admin";
				newSub = adminId;
				mutation = `Changed sub to admin identifier '${newSub}'`;
				break;
			}

			case "empty":
				newSub = "";
				mutation = "Set sub to empty string";
				break;

			case "numeric": {
				// Use numeric ID (type confusion attack)
				newSub = (ctx.config.numericId as number | undefined) ?? 1;
				mutation = "Changed sub to numeric value (type confusion)";
				break;
			}

			default:
				return {
					applied: false,
					mutation: `Unknown mode: ${mode}`,
					evidence: { mode },
				};
		}

		ctx.token.claims.sub = newSub as string;

		return {
			applied: true,
			mutation,
			evidence: {
				mode,
				originalSubject: originalSub,
				newSubject: newSub,
				attackType: "subject-manipulation",
			},
		};
	},
};
