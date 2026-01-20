/**
 * Built-in mischief plugins
 */

export { algNonePlugin } from "./alg-none.js";
export { keyConfusionPlugin } from "./key-confusion.js";
export { latencyInjectionPlugin } from "./latency-injection.js";
export { temporalTamperingPlugin } from "./temporal-tampering.js";

import type { MischiefPlugin } from "../types.js";
import { algNonePlugin } from "./alg-none.js";
import { keyConfusionPlugin } from "./key-confusion.js";
import { latencyInjectionPlugin } from "./latency-injection.js";
import { temporalTamperingPlugin } from "./temporal-tampering.js";

/**
 * All built-in plugins
 */
export const builtInPlugins: MischiefPlugin[] = [
	algNonePlugin,
	keyConfusionPlugin,
	latencyInjectionPlugin,
	temporalTamperingPlugin,
];
