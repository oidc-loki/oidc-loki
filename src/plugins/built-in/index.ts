/**
 * Built-in mischief plugins
 *
 * Organized by attack category:
 * - Signature attacks: alg-none, key-confusion, kid-manipulation, token-type-confusion
 * - Claims attacks: issuer-confusion, audience-confusion, subject-manipulation, temporal-tampering, scope-injection
 * - Flow attacks: nonce-bypass, state-bypass, pkce-downgrade
 * - Discovery attacks: discovery-confusion, jwks-injection
 * - Resilience: latency-injection
 */

// Signature/Algorithm attacks
export { algNonePlugin } from "./alg-none.js";
export { keyConfusionPlugin } from "./key-confusion.js";
export { kidManipulationPlugin } from "./kid-manipulation.js";
export { tokenTypeConfusionPlugin } from "./token-type-confusion.js";

// Claims manipulation attacks
export { issuerConfusionPlugin } from "./issuer-confusion.js";
export { audienceConfusionPlugin } from "./audience-confusion.js";
export { subjectManipulationPlugin } from "./subject-manipulation.js";
export { temporalTamperingPlugin } from "./temporal-tampering.js";
export { scopeInjectionPlugin } from "./scope-injection.js";

// Flow/Protocol attacks
export { nonceBypassPlugin } from "./nonce-bypass.js";
export { stateBypassPlugin } from "./state-bypass.js";
export { pkceDowngradePlugin } from "./pkce-downgrade.js";

// Discovery/JWKS attacks
export { discoveryConfusionPlugin } from "./discovery-confusion.js";
export { jwksInjectionPlugin } from "./jwks-injection.js";

// Resilience testing
export { latencyInjectionPlugin } from "./latency-injection.js";

import type { MischiefPlugin } from "../types.js";
import { algNonePlugin } from "./alg-none.js";
import { audienceConfusionPlugin } from "./audience-confusion.js";
import { discoveryConfusionPlugin } from "./discovery-confusion.js";
import { issuerConfusionPlugin } from "./issuer-confusion.js";
import { jwksInjectionPlugin } from "./jwks-injection.js";
import { keyConfusionPlugin } from "./key-confusion.js";
import { kidManipulationPlugin } from "./kid-manipulation.js";
import { latencyInjectionPlugin } from "./latency-injection.js";
import { nonceBypassPlugin } from "./nonce-bypass.js";
import { pkceDowngradePlugin } from "./pkce-downgrade.js";
import { scopeInjectionPlugin } from "./scope-injection.js";
import { stateBypassPlugin } from "./state-bypass.js";
import { subjectManipulationPlugin } from "./subject-manipulation.js";
import { temporalTamperingPlugin } from "./temporal-tampering.js";
import { tokenTypeConfusionPlugin } from "./token-type-confusion.js";

/**
 * All built-in plugins
 */
export const builtInPlugins: MischiefPlugin[] = [
	// Critical severity - signature bypass
	algNonePlugin,
	keyConfusionPlugin,

	// Critical severity - identity spoofing
	issuerConfusionPlugin,
	audienceConfusionPlugin,
	subjectManipulationPlugin,
	scopeInjectionPlugin,

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

	// Medium severity - resilience
	latencyInjectionPlugin,
];
