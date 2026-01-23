/**
 * Built-in mischief plugins
 *
 * Organized by attack category:
 * - Signature attacks: alg-none, key-confusion, kid-manipulation, token-type-confusion, weak-algorithms, jku-injection, x5u-injection, embedded-jwk-attack, crit-header-bypass, curve-confusion
 * - Claims attacks: issuer-confusion, audience-confusion, subject-manipulation, temporal-tampering, scope-injection, azp-confusion, at-hash-c-hash-mismatch, token-lifetime-abuse, claim-type-coercion, unicode-normalization, json-parsing-differentials
 * - Flow attacks: nonce-bypass, state-bypass, pkce-downgrade, response-mode-mismatch, iss-in-response-attack, response-type-confusion
 * - Discovery attacks: discovery-confusion, jwks-injection, jwks-domain-mismatch, massive-jwks, massive-metadata
 * - Resilience: latency-injection, massive-token, error-injection, partial-success
 */

// Signature/Algorithm attacks
export { algNonePlugin } from "./alg-none.js";
export { keyConfusionPlugin } from "./key-confusion.js";
export { kidManipulationPlugin } from "./kid-manipulation.js";
export { tokenTypeConfusionPlugin } from "./token-type-confusion.js";
export { weakAlgorithms } from "./weak-algorithms.js";
export { jkuInjection } from "./jku-injection.js";
export { x5uInjection } from "./x5u-injection.js";
export { embeddedJwkAttack } from "./embedded-jwk-attack.js";
export { critHeaderBypass } from "./crit-header-bypass.js";
export { curveConfusion } from "./curve-confusion.js";

// Claims manipulation attacks
export { issuerConfusionPlugin } from "./issuer-confusion.js";
export { audienceConfusionPlugin } from "./audience-confusion.js";
export { subjectManipulationPlugin } from "./subject-manipulation.js";
export { temporalTamperingPlugin } from "./temporal-tampering.js";
export { scopeInjectionPlugin } from "./scope-injection.js";
export { azpConfusion } from "./azp-confusion.js";
export { atHashCHashMismatch } from "./at-hash-c-hash-mismatch.js";
export { tokenLifetimeAbuse } from "./token-lifetime-abuse.js";
export { claimTypeCoercion } from "./claim-type-coercion.js";
export { unicodeNormalization } from "./unicode-normalization.js";
export { jsonParsingDifferentials } from "./json-parsing-differentials.js";

// Flow/Protocol attacks
export { nonceBypassPlugin } from "./nonce-bypass.js";
export { stateBypassPlugin } from "./state-bypass.js";
export { pkceDowngradePlugin } from "./pkce-downgrade.js";
export { responseModeMismatch } from "./response-mode-mismatch.js";
export { issInResponseAttack } from "./iss-in-response-attack.js";
export { responseTypeConfusion } from "./response-type-confusion.js";

// Discovery/JWKS attacks
export { discoveryConfusionPlugin } from "./discovery-confusion.js";
export { jwksInjectionPlugin } from "./jwks-injection.js";
export { jwksDomainMismatch } from "./jwks-domain-mismatch.js";
export { massiveJwks } from "./massive-jwks.js";
export { massiveMetadata } from "./massive-metadata.js";

// Resilience testing
export { latencyInjectionPlugin } from "./latency-injection.js";
export { massiveToken } from "./massive-token.js";
export { errorInjection } from "./error-injection.js";
export { partialSuccess } from "./partial-success.js";

import type { MischiefPlugin } from "../types.js";
import { algNonePlugin } from "./alg-none.js";
import { atHashCHashMismatch } from "./at-hash-c-hash-mismatch.js";
import { audienceConfusionPlugin } from "./audience-confusion.js";
import { azpConfusion } from "./azp-confusion.js";
import { claimTypeCoercion } from "./claim-type-coercion.js";
import { critHeaderBypass } from "./crit-header-bypass.js";
import { curveConfusion } from "./curve-confusion.js";
import { discoveryConfusionPlugin } from "./discovery-confusion.js";
import { embeddedJwkAttack } from "./embedded-jwk-attack.js";
import { errorInjection } from "./error-injection.js";
import { issInResponseAttack } from "./iss-in-response-attack.js";
import { issuerConfusionPlugin } from "./issuer-confusion.js";
import { jkuInjection } from "./jku-injection.js";
import { jsonParsingDifferentials } from "./json-parsing-differentials.js";
import { jwksDomainMismatch } from "./jwks-domain-mismatch.js";
import { jwksInjectionPlugin } from "./jwks-injection.js";
import { keyConfusionPlugin } from "./key-confusion.js";
import { kidManipulationPlugin } from "./kid-manipulation.js";
import { latencyInjectionPlugin } from "./latency-injection.js";
import { massiveJwks } from "./massive-jwks.js";
import { massiveMetadata } from "./massive-metadata.js";
import { massiveToken } from "./massive-token.js";
import { nonceBypassPlugin } from "./nonce-bypass.js";
import { partialSuccess } from "./partial-success.js";
import { pkceDowngradePlugin } from "./pkce-downgrade.js";
import { responseModeMismatch } from "./response-mode-mismatch.js";
import { responseTypeConfusion } from "./response-type-confusion.js";
import { scopeInjectionPlugin } from "./scope-injection.js";
import { stateBypassPlugin } from "./state-bypass.js";
import { subjectManipulationPlugin } from "./subject-manipulation.js";
import { temporalTamperingPlugin } from "./temporal-tampering.js";
import { tokenLifetimeAbuse } from "./token-lifetime-abuse.js";
import { tokenTypeConfusionPlugin } from "./token-type-confusion.js";
import { unicodeNormalization } from "./unicode-normalization.js";
import { weakAlgorithms } from "./weak-algorithms.js";
import { x5uInjection } from "./x5u-injection.js";

/**
 * All built-in plugins (36 total)
 */
export const builtInPlugins: MischiefPlugin[] = [
	// Critical severity - signature bypass
	algNonePlugin,
	keyConfusionPlugin,
	weakAlgorithms,
	jkuInjection,
	x5uInjection,
	embeddedJwkAttack,
	curveConfusion,
	jwksDomainMismatch,

	// Critical severity - identity spoofing
	issuerConfusionPlugin,
	audienceConfusionPlugin,
	subjectManipulationPlugin,
	scopeInjectionPlugin,
	issInResponseAttack,

	// Critical severity - discovery attacks
	discoveryConfusionPlugin,
	jwksInjectionPlugin,

	// High severity - key/flow attacks
	kidManipulationPlugin,
	tokenTypeConfusionPlugin,
	temporalTamperingPlugin,
	nonceBypassPlugin,
	stateBypassPlugin,
	pkceDowngradePlugin,
	critHeaderBypass,
	azpConfusion,
	atHashCHashMismatch,
	tokenLifetimeAbuse,
	responseTypeConfusion,

	// Medium severity - resilience & parsing
	latencyInjectionPlugin,
	massiveToken,
	massiveJwks,
	massiveMetadata,
	responseModeMismatch,
	claimTypeCoercion,
	unicodeNormalization,
	jsonParsingDifferentials,
	errorInjection,
	partialSuccess,
];

/**
 * Attack profiles for grouped testing
 */
export const attackProfiles: Record<string, string[]> = {
	"full-scan": builtInPlugins.map((p) => p.id),
	"critical-only": builtInPlugins.filter((p) => p.severity === "critical").map((p) => p.id),
	"token-validation": [
		"alg-none",
		"key-confusion",
		"weak-algorithms",
		"jku-injection",
		"x5u-injection",
		"embedded-jwk-attack",
		"curve-confusion",
		"kid-manipulation",
		"token-type-confusion",
		"crit-header-bypass",
	],
	"discovery-attacks": [
		"discovery-confusion",
		"jwks-injection",
		"jwks-domain-mismatch",
		"massive-jwks",
		"massive-metadata",
	],
	"flow-attacks": [
		"nonce-bypass",
		"state-bypass",
		"pkce-downgrade",
		"response-mode-mismatch",
		"iss-in-response-attack",
		"response-type-confusion",
	],
	resilience: [
		"latency-injection",
		"massive-token",
		"massive-jwks",
		"massive-metadata",
		"error-injection",
		"partial-success",
	],
	"parsing-attacks": ["claim-type-coercion", "unicode-normalization", "json-parsing-differentials"],
};

/**
 * Get all plugin IDs
 */
export function getAllPluginIds(): string[] {
	return builtInPlugins.map((p) => p.id);
}
