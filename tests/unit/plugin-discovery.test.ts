import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PluginRegistry } from "../../src/plugins/registry.js";

describe("Plugin Discovery", () => {
	const TEST_PLUGINS_DIR = "./test-plugins";

	beforeEach(() => {
		// Clean up and create test directory
		if (existsSync(TEST_PLUGINS_DIR)) {
			rmSync(TEST_PLUGINS_DIR, { recursive: true, force: true });
		}
		mkdirSync(TEST_PLUGINS_DIR, { recursive: true });
	});

	afterEach(() => {
		if (existsSync(TEST_PLUGINS_DIR)) {
			rmSync(TEST_PLUGINS_DIR, { recursive: true, force: true });
		}
	});

	it("should load plugins from custom directory", async () => {
		// Create a valid plugin file
		const pluginCode = `
export const testPlugin = {
	id: "test-custom-plugin",
	name: "Test Custom Plugin",
	severity: "low",
	phase: "response",
	spec: {
		description: "Test plugin for discovery"
	},
	description: "A test plugin",
	async apply(ctx) {
		return { applied: false, mutation: "test", evidence: {} };
	}
};
`;
		writeFileSync(`${TEST_PLUGINS_DIR}/test-plugin.js`, pluginCode);

		const registry = new PluginRegistry({ customDir: TEST_PLUGINS_DIR });
		await registry.loadBuiltIn();
		await registry.discoverCustom();

		expect(registry.has("test-custom-plugin")).toBe(true);
		expect(registry.count).toBe(12); // 11 built-in + 1 custom
	});

	it("should load plugin with default export", async () => {
		const pluginCode = `
export default {
	id: "default-export-plugin",
	name: "Default Export Plugin",
	severity: "medium",
	phase: "token-claims",
	spec: { description: "Testing default export" },
	description: "Plugin using default export",
	async apply(ctx) {
		return { applied: false, mutation: "none", evidence: {} };
	}
};
`;
		writeFileSync(`${TEST_PLUGINS_DIR}/default-plugin.js`, pluginCode);

		const registry = new PluginRegistry({ customDir: TEST_PLUGINS_DIR });
		await registry.discoverCustom();

		expect(registry.has("default-export-plugin")).toBe(true);
	});

	it("should load multiple plugins from one file", async () => {
		const pluginCode = `
export const pluginA = {
	id: "multi-plugin-a",
	name: "Multi Plugin A",
	severity: "low",
	phase: "response",
	spec: { description: "First plugin" },
	description: "First of two plugins",
	async apply(ctx) {
		return { applied: false, mutation: "none", evidence: {} };
	}
};

export const pluginB = {
	id: "multi-plugin-b",
	name: "Multi Plugin B",
	severity: "high",
	phase: "token-signing",
	spec: { description: "Second plugin" },
	description: "Second of two plugins",
	async apply(ctx) {
		return { applied: false, mutation: "none", evidence: {} };
	}
};
`;
		writeFileSync(`${TEST_PLUGINS_DIR}/multi-plugin.js`, pluginCode);

		const registry = new PluginRegistry({ customDir: TEST_PLUGINS_DIR });
		await registry.discoverCustom();

		expect(registry.has("multi-plugin-a")).toBe(true);
		expect(registry.has("multi-plugin-b")).toBe(true);
		expect(registry.count).toBe(2);
	});

	it("should respect disabled plugins", async () => {
		const pluginCode = `
export const disabledPlugin = {
	id: "should-be-disabled",
	name: "Disabled Plugin",
	severity: "low",
	phase: "response",
	spec: { description: "This will be disabled" },
	description: "Should not be registered",
	async apply(ctx) {
		return { applied: false, mutation: "none", evidence: {} };
	}
};
`;
		writeFileSync(`${TEST_PLUGINS_DIR}/disabled-plugin.js`, pluginCode);

		const registry = new PluginRegistry({
			customDir: TEST_PLUGINS_DIR,
			disabled: ["should-be-disabled"],
		});
		await registry.discoverCustom();

		expect(registry.has("should-be-disabled")).toBe(false);
		expect(registry.count).toBe(0);
	});

	it("should skip invalid plugin exports", async () => {
		// Missing required fields
		const invalidPluginCode = `
export const invalidPlugin = {
	id: "invalid-plugin",
	name: "Invalid Plugin",
	// Missing severity, phase, spec, description, apply
};

export const validPlugin = {
	id: "valid-plugin",
	name: "Valid Plugin",
	severity: "low",
	phase: "response",
	spec: { description: "Valid" },
	description: "Valid plugin",
	async apply(ctx) {
		return { applied: false, mutation: "none", evidence: {} };
	}
};
`;
		writeFileSync(`${TEST_PLUGINS_DIR}/mixed-validity.js`, invalidPluginCode);

		const registry = new PluginRegistry({ customDir: TEST_PLUGINS_DIR });
		await registry.discoverCustom();

		expect(registry.has("invalid-plugin")).toBe(false);
		expect(registry.has("valid-plugin")).toBe(true);
		expect(registry.count).toBe(1);
	});

	it("should skip non-plugin directories silently", async () => {
		const registry = new PluginRegistry({ customDir: "./nonexistent-dir" });
		await expect(registry.discoverCustom()).resolves.not.toThrow();
		expect(registry.count).toBe(0);
	});

	it("should skip .d.ts files", async () => {
		// Create a .d.ts file that would be invalid JS
		writeFileSync(`${TEST_PLUGINS_DIR}/types.d.ts`, "declare module 'test';");

		// Create a valid plugin
		const pluginCode = `
export const realPlugin = {
	id: "real-plugin",
	name: "Real Plugin",
	severity: "low",
	phase: "response",
	spec: { description: "Real" },
	description: "Real plugin",
	async apply(ctx) {
		return { applied: false, mutation: "none", evidence: {} };
	}
};
`;
		writeFileSync(`${TEST_PLUGINS_DIR}/real-plugin.js`, pluginCode);

		const registry = new PluginRegistry({ customDir: TEST_PLUGINS_DIR });
		await registry.discoverCustom();

		expect(registry.has("real-plugin")).toBe(true);
		expect(registry.count).toBe(1);
	});

	it("should handle plugin load errors gracefully", async () => {
		// Create a file with syntax error
		writeFileSync(`${TEST_PLUGINS_DIR}/broken.js`, "export const broken = { syntax error here");

		// Create a valid plugin
		const pluginCode = `
export const goodPlugin = {
	id: "good-plugin",
	name: "Good Plugin",
	severity: "low",
	phase: "response",
	spec: { description: "Good" },
	description: "Good plugin",
	async apply(ctx) {
		return { applied: false, mutation: "none", evidence: {} };
	}
};
`;
		writeFileSync(`${TEST_PLUGINS_DIR}/good-plugin.js`, pluginCode);

		const registry = new PluginRegistry({ customDir: TEST_PLUGINS_DIR });
		// Should not throw, just warn
		await expect(registry.discoverCustom()).resolves.not.toThrow();

		// Good plugin should still be loaded
		expect(registry.has("good-plugin")).toBe(true);
	});
});
